// src/core/PlayerTracker.ts
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
  private config: any;

  private constructor() {
    this.players = new Map();
    this.logger = Logger.getInstance();
    this.listManager = ListManager.getInstance();
    this.ipChecker = IpChecker.getInstance();
    this.webhookService = WebhookService.getInstance();
    this.cache = CacheService.getInstance();
    this.config = ConfigManager.getInstance().getAll();
    this.logger.info(`🔧 Mode: ${this.getMode().toUpperCase()} (AutoBan: ${this.isAutoBanEnabled() ? 'ON' : 'OFF'})`);
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
      if (!currentIds.has(id)) this.players.delete(id); 
    }

    const playersToCheck: StatusPlayer[] = [];
    for (const sp of statusPlayers) {
      if (sp.nickname === 'LythorixAntiVpn') continue;

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
    try {
      const result = await this.ipChecker.checkIp(sp.ip, sp.nickname);
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
        this.logger.warn(`🚨 SUSPICIOUS: ${sp.nickname} (${sp.ip}) - Score: ${result.risk_score}`);
        try { await this.webhookService.sendVpnDetectionAlert(tracked, result); } catch (e) {}
        
        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && !this.bannedIps.has(sp.ip)) {
          await this.autoBan(sp, result);
        } else if (this.getMode() === 'warn') {
          await this.webhookService.sendWarning('⚠️ Warn Mode', `**${sp.nickname}** VPN/прокси. Бан не выполнен.`, [
            { name: 'IP', value: `\`${sp.ip}\``, inline: true }, 
            { name: 'ID', value: String(sp.id), inline: true }
          ]);
        }
      } else {
        this.logger.info(`✅ Clean: ${sp.nickname} (${sp.ip})`);
        try { await this.webhookService.sendCleanPlayerInfo(tracked, result); } catch (e) {}
      }
    } catch (error) {
      this.trackPlayer(sp, { 
        is_whitelisted: false, is_blacklisted: false, is_vpn: false, 
        is_proxy: false, is_suspicious: false, is_trusted: true 
      });
    }
  }

  async checkPlayerOnLeave(clientId: number): Promise<void> {
    const player = this.players.get(clientId);
    
    if (!player) {
      this.logger.debug(`Player ID=${clientId} not found, skipping`);
      return;
    }
    
    if (this.bannedIps.has(player.ip)) {
      this.logger.debug(`IP ${player.ip} already banned`);
      return;
    }
    
    if (player.flags.is_trusted && player.ip_check) {
      this.logger.debug(`${player.nickname} already checked as clean`);
      return;
    }
    
    if (this.listManager.isWhitelisted(player.ip)) {
      this.logger.debug(`IP ${player.ip} whitelisted`);
      return;
    }
    
    this.logger.info(`🔍 Checking IP after leave: ${player.nickname} (${player.ip})`);
    
    try {
      const result = await this.ipChecker.checkIp(player.ip, player.nickname);
      const sus = result.is_vpn || result.is_proxy || result.is_tor || result.is_hosting || result.is_datacenter;
      
      player.flags = { 
        is_whitelisted: !sus, is_blacklisted: sus, is_vpn: result.is_vpn, 
        is_proxy: result.is_proxy, is_suspicious: sus, is_trusted: !sus 
      };
      player.ip_check = result;
      
      if (sus) {
        this.logger.warn(`🚨 Player left but VPN detected: ${player.nickname} (${player.ip})`);
        try { await this.webhookService.sendVpnDetectionAlert(player, result); } catch (e) {}
        
        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && !this.bannedIps.has(player.ip)) {
          await this.autoBan({
            id: player.id, nickname: player.nickname, clan: player.clan,
            ip: player.ip, score: 0, latency: 0
          }, result);
        }
      } else {
        this.logger.info(`✅ Player left, IP clean: ${player.nickname}`);
      }
    } catch (error) {
      this.logger.error(`Failed to check IP for left player`, error);
    }
  }

  private async autoBan(player: StatusPlayer, ipCheck?: IpCheckResult): Promise<void> {
    if (!this.rconService) return;
    
    const reason = 'Vpn/Proxy detected. Disable your vpn/proxy to play. If you think this a mistake contact bot owner (@LythorixContactBot)';
    const banMinutes = this.config.auto_ban?.ban_duration_minutes || 10;
    
    try {
      await this.rconService.execute(`ban ${player.ip} ${banMinutes} "${reason}"`);
      this.bannedIps.add(player.ip);
      this.logger.warn(`🔨 AUTO-BANNED: ${player.nickname} (${player.ip}) - ${banMinutes}min`);
      
      await this.webhookService.sendInfo('🔨 Auto-Ban', `**${player.nickname}** забанен за VPN/прокси`, [
        { name: 'IP', value: `\`${player.ip}\``, inline: true },
        { name: 'ID', value: String(player.id), inline: true },
        { name: 'Причина', value: reason, inline: false },
        { name: 'Длительность', value: `${banMinutes} минут`, inline: true },
        { name: 'Режим', value: 'AUTOBAN', inline: true }
      ]);
    } catch (error) { 
      this.logger.error(`Failed to auto-ban ${player.nickname}`, error); 
    }
  }

  private trackPlayer(sp: StatusPlayer, flags: TrackedPlayer['flags'], ipCheck?: IpCheckResult): TrackedPlayer {
    const ex = this.players.get(sp.id);
    const player: TrackedPlayer = {
      id: sp.id, nickname: sp.nickname, clan: sp.clan || '', ip: sp.ip,
      first_seen: ex?.first_seen || new Date().toISOString(),
      last_seen: new Date().toISOString(),
      sessions: (ex?.sessions || 0) + 1, flags, ip_check: ipCheck
    };
    this.players.set(sp.id, player);
    return player;
  }

  private delay(ms: number): Promise<void> { 
    return new Promise(r => setTimeout(r, ms)); 
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
  }
}