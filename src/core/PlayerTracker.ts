// src/core/PlayerTracker.ts - ADD CONNECTING PLAYERS CHECK
import { TrackedPlayer, IpCheckResult, StatusPlayer } from '../types';
import { Logger } from '../utils/Logger';
import { ListManager } from '../services/ListManager';
import { IpChecker } from '../services/IpChecker';
import { WebhookService } from '../services/WebhookService';
import { CacheService } from '../utils/Cache';
import { ConfigManager } from '../config/ConfigManager';

export class PlayerTracker {
  private static instance: PlayerTracker;
  private players: Map<number, TrackedPlayer>;
  private logger: Logger;
  private listManager: ListManager;
  private ipChecker: IpChecker;
  private webhookService: WebhookService;
  private cache: CacheService;
  private rconService: any;
  private bannedIps: Set<string> = new Set();
  private checkingIps: Set<string> = new Set();
  private leaveCheckedIds: Set<number> = new Set();
  private config: any;
  private botNickname: string;

  private constructor() {
    this.players = new Map();
    this.logger = Logger.getInstance();
    this.listManager = ListManager.getInstance();
    this.ipChecker = IpChecker.getInstance();
    this.webhookService = WebhookService.getInstance();
    this.cache = CacheService.getInstance();
    this.config = ConfigManager.getInstance().getAll();
    this.botNickname = this.config.bot?.nickname || 'LythorixAntiVpn';
    this.logger.info(`Mode: ${this.getMode().toUpperCase()} (AutoBan: ${this.isAutoBanEnabled() ? 'ON' : 'OFF'})`);
  }

  static getInstance(): PlayerTracker { 
    return PlayerTracker.instance || (PlayerTracker.instance = new PlayerTracker()); 
  }

  setRconService(rconService: any): void { 
    this.rconService = rconService; 
  }

  private getMode(): 'warn' | 'autoban' { 
    return this.config.auto_ban?.mode || 'warn'; 
  }

  private isAutoBanEnabled(): boolean { 
    return this.config.auto_ban?.enabled ?? false; 
  }

  async processStatus(statusPlayers: StatusPlayer[]): Promise<void> {
    const currentIds = new Set(statusPlayers.map(p => p.id));
    for (const [id] of this.players) {
      if (!currentIds.has(id)) {
        await this.checkPlayerOnLeave(id);
        this.players.delete(id);
      }
    }

    const playersToCheck: StatusPlayer[] = [];
    for (const sp of statusPlayers) {
      if (sp.nickname === this.botNickname) continue;

      // CHECK CONNECTING PLAYERS (no nickname yet)
      const isConnecting = sp.nickname === 'connecting' || sp.nickname.startsWith('connecting');
      
      if (isConnecting) {
        if (!this.checkingIps.has(sp.ip) && !this.listManager.isWhitelisted(sp.ip) && !this.listManager.isPrivateIP(sp.ip)) {
          playersToCheck.push(sp);
        }
        continue;
      }

      if (this.listManager.isWhitelisted(sp.ip) || this.listManager.isPrivateIP(sp.ip)) {
        this.trackPlayer(sp, { 
          is_whitelisted: true, is_blacklisted: false, is_vpn: false, 
          is_proxy: false, is_suspicious: false, is_trusted: true 
        });
        continue;
      }

      if (this.listManager.isBlacklisted(sp.ip)) {
        this.trackPlayer(sp, { 
          is_whitelisted: false, is_blacklisted: true, is_vpn: true, 
          is_proxy: false, is_suspicious: true, is_trusted: false 
        });
        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && !this.bannedIps.has(sp.ip)) {
          await this.autoBan(sp);
        }
        continue;
      }

      const cached = this.cache.get(sp.ip);
      if (cached) {
        const sus = cached.is_vpn || cached.is_proxy || cached.is_tor || cached.is_hosting || cached.is_datacenter;
        this.trackPlayer(sp, { 
          is_whitelisted: !sus, is_blacklisted: sus, is_vpn: cached.is_vpn, 
          is_proxy: cached.is_proxy, is_suspicious: sus, is_trusted: !sus 
        }, cached);
        if (sus && this.getMode() === 'autoban' && this.isAutoBanEnabled() && !this.bannedIps.has(sp.ip)) {
          await this.autoBan(sp, cached);
        }
        if (!sus) {
          this.listManager.addToWhitelist(sp.ip, `Auto: ${cached.isp} (${cached.country})`);
        }
        continue;
      }

      playersToCheck.push(sp);
    }

    if (playersToCheck.length > 0) {
      for (let i = 0; i < playersToCheck.length; i += 10) {
        await Promise.allSettled(playersToCheck.slice(i, i + 10).map(p => this.checkIpForPlayer(p)));
        if (i + 10 < playersToCheck.length) await this.delay(500);
      }
    }
  }

  async checkIpForPlayer(sp: StatusPlayer): Promise<void> {
    if (this.checkingIps.has(sp.ip)) return;
    this.checkingIps.add(sp.ip);

    try {
      const result = await this.ipChecker.checkIp(sp.ip);
      const sus = result.is_vpn || result.is_proxy || result.is_tor || result.is_hosting || result.is_datacenter;
      const flags = { 
        is_whitelisted: !sus && result.risk_score < 30, 
        is_blacklisted: sus, 
        is_vpn: result.is_vpn, 
        is_proxy: result.is_proxy, 
        is_suspicious: sus, 
        is_trusted: !sus 
      };
      const tracked = this.trackPlayer(sp, flags, result);

      if (sus) {
        const name = sp.nickname === 'connecting' ? 'Unknown' : sp.nickname;
        this.logger.warn(`SUSPICIOUS: ${name} (${sp.ip}) - Score: ${result.risk_score}`);

        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && !this.bannedIps.has(sp.ip)) {
          await this.autoBan(sp, result);
        }

        try { await this.webhookService.sendVpnDetectionAlert(tracked, result); } catch (e) {}
      } else {
        const name = sp.nickname === 'connecting' ? 'Unknown' : sp.nickname;
        this.logger.info(`Clean: ${name} (${sp.ip})`);
        this.listManager.addToWhitelist(sp.ip, `Auto: ${result.isp} (${result.country})`);
        try { await this.webhookService.sendCleanPlayerInfo(tracked, result); } catch (e) {}
      }
    } catch (error) {
      this.logger.error(`IP check failed for ${sp.nickname} (${sp.ip})`, error);
      this.trackPlayer(sp, {
        is_whitelisted: false, is_blacklisted: false, is_vpn: false,
        is_proxy: false, is_suspicious: false, is_trusted: true
      });
    } finally {
      this.checkingIps.delete(sp.ip);
    }
  }

  async checkPlayerOnLeave(clientId: number): Promise<void> {
    if (this.leaveCheckedIds.has(clientId)) return;

    const player = this.players.get(clientId);
    
    if (!player) return;
    if (this.bannedIps.has(player.ip)) return;
    if (player.flags.is_trusted && player.ip_check) return;
    if (this.listManager.isWhitelisted(player.ip)) return;
    
    this.leaveCheckedIds.add(clientId);
    this.logger.info(`Checking IP after leave: ${player.nickname} (${player.ip})`);
    
    try {
      const result = await this.ipChecker.checkIp(player.ip);
      const sus = result.is_vpn || result.is_proxy || result.is_tor || result.is_hosting || result.is_datacenter;
      
      player.flags = { 
        is_whitelisted: !sus, is_blacklisted: sus, is_vpn: result.is_vpn, 
        is_proxy: result.is_proxy, is_suspicious: sus, is_trusted: !sus 
      };
      player.ip_check = result;
      
      if (sus) {
        this.logger.warn(`Player left but VPN detected: ${player.nickname} (${player.ip})`);

        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && !this.bannedIps.has(player.ip)) {
          await this.autoBan({
            id: player.id, nickname: player.nickname, clan: player.clan,
            ip: player.ip, score: 0, latency: 0
          }, result);
        }

        try { await this.webhookService.sendVpnDetectionAlert(player, result); } catch (e) {}
      } else {
        this.logger.info(`Player left, IP clean: ${player.nickname}`);
        this.listManager.addToWhitelist(player.ip, `Auto: ${result.isp} (${result.country})`);
      }
    } catch (error) {
      this.logger.error(`Failed to check IP for left player`, error);
    }
  }

  private async autoBan(player: StatusPlayer, ipCheck?: IpCheckResult): Promise<void> {
    if (!this.rconService) return;
    
    const reason = 'VPN/Proxy detected. Appeal: @LythorixContactBot';
    const banMinutes = this.config.auto_ban?.ban_duration_minutes || 0;
    
    try {
      await this.rconService.execute(`ban ${player.ip} ${banMinutes} "${reason}"`);
      this.bannedIps.add(player.ip);
      this.logger.warn(`AUTO-BANNED: ${player.nickname} (${player.ip})`);
      
      await this.webhookService.sendAutoBan(
        this.players.get(player.id) || {
          id: player.id,
          nickname: player.nickname,
          clan: player.clan || '',
          ip: player.ip,
          first_seen: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          sessions: 1,
          flags: { is_whitelisted: false, is_blacklisted: true, is_vpn: true, is_proxy: false, is_suspicious: true, is_trusted: false },
          ip_check: ipCheck
        },
        ipCheck || { ip: player.ip, is_vpn: true, is_proxy: false, is_tor: false, is_hosting: false, is_datacenter: false, risk_score: 100, threat_level: 'critical', checked_at: new Date().toISOString(), cached: false }
      );
    } catch (error) { 
      this.logger.error(`Failed to auto-ban ${player.nickname}`, error); 
    }
  }

  private trackPlayer(sp: StatusPlayer, flags: TrackedPlayer['flags'], ipCheck?: IpCheckResult): TrackedPlayer {
    const ex = this.players.get(sp.id);
    const nickname = this.isPlaceholderName(sp.nickname) && ex ? ex.nickname : sp.nickname;
    const clan = sp.clan || ex?.clan || '';
    const player: TrackedPlayer = {
      id: sp.id, nickname, clan, ip: sp.ip,
      first_seen: ex?.first_seen || new Date().toISOString(),
      last_seen: new Date().toISOString(),
      sessions: ex ? ex.sessions : 1, flags, ip_check: ipCheck
    };
    this.players.set(sp.id, player);
    if (!ex) this.leaveCheckedIds.delete(sp.id);
    return player;
  }

  private delay(ms: number): Promise<void> { 
    return new Promise(r => setTimeout(r, ms)); 
  }

  private isPlaceholderName(nickname: string): boolean {
    return !nickname ||
      nickname === 'Unknown' ||
      /^Player_\d+$/i.test(nickname) ||
      /^Left_Player_\d+$/i.test(nickname);
  }

  getPlayer(id: number): TrackedPlayer | undefined { 
    return this.players.get(id); 
  }

  getAllPlayers(): TrackedPlayer[] { 
    return Array.from(this.players.values()); 
  }

  getSuspiciousPlayers(): TrackedPlayer[] { 
    return this.getAllPlayers().filter(p => p.flags.is_suspicious); 
  }

  getStats(): { 
    total: number; whitelisted: number; blacklisted: number; 
    suspicious: number; clean: number; banned: number; mode: string;
  } {
    const all = this.getAllPlayers();
    return {
      total: all.length,
      whitelisted: all.filter(p => this.listManager.isWhitelisted(p.ip)).length,
      blacklisted: all.filter(p => this.listManager.isBlacklisted(p.ip)).length,
      suspicious: all.filter(p => p.flags.is_suspicious).length,
      clean: all.filter(p => !p.flags.is_suspicious && !this.listManager.isBlacklisted(p.ip)).length,
      banned: this.bannedIps.size,
      mode: this.getMode()
    };
  }

  clear(): void { 
    this.players.clear();
    this.leaveCheckedIds.clear();
  }
}