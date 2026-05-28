// src/core/SessionManager.ts
import { Logger } from '../utils/Logger';
import { RconService } from '../services/RconService';
import { WebhookService } from '../services/WebhookService';
import { PlayerTracker } from './PlayerTracker';
import { ListManager } from '../services/ListManager';
import { CacheService } from '../utils/Cache';
import { AppConfig, StatusPlayer } from '../types';

export class SessionManager {
  private client: any;
  private config: AppConfig;
  private logger: Logger;
  private rconService: RconService;
  private webhookService: WebhookService;
  private playerTracker: PlayerTracker;
  private listManager: ListManager;
  private cache: CacheService;
  private isRunning: boolean = false;
  private reconnectAttempts: number = 0;
  private statusInterval: NodeJS.Timeout | null = null;
  private playerIpHistory: Map<number, string> = new Map();
  private joinListenerActive: boolean = false;

  constructor(client: any, config: AppConfig) {
    this.client = client;
    this.config = config;
    this.logger = Logger.getInstance();
    this.rconService = new RconService(client);
    this.webhookService = WebhookService.getInstance();
    this.playerTracker = PlayerTracker.getInstance();
    this.listManager = ListManager.getInstance();
    this.cache = CacheService.getInstance();
    this.client.on('connected', () => this.onConnected());
    this.client.on('disconnect', (r: string, f: boolean) => this.onDisconnect(r, f));
  }

  private async onConnected(): Promise<void> {
    this.reconnectAttempts = 0;
    this.isRunning = true;
    this.playerIpHistory.clear();
    this.joinListenerActive = false;
    
    try {
      this.client.game.SetTeam(-1);
      await this.rconService.login(this.config.server.rcon_password, this.config.server.rcon_username);
      this.playerTracker.setRconService(this.rconService);

      this.rconService.execute('hide_auth_status 1');
      this.rconService.execute('show_ips 1');

      const ws = this.listManager.getWhitelistStats();
      const bs = this.listManager.getBlacklistStats();
      this.webhookService.sendStartupMessage({ 
        server: `${this.config.server.host}:${this.config.server.port}`, 
        whitelist: ws.ips, 
        blacklist: bs.ips 
      });

      await this.initialStatusCheck();
      this.setupJoinListener();
      this.joinListenerActive = true;
      
      this.statusInterval = setInterval(() => this.checkStatus(), this.config.monitoring.status_interval_seconds * 1000);
      this.logger.info('✅ Ready');
    } catch (error) { this.logger.error('Init failed', error); }
  }

  private async initialStatusCheck(): Promise<void> {
    try {
      const status = await this.rconService.executeStatus();
      if (status.players.length > 0) {
        for (const p of status.players) this.playerIpHistory.set(p.id, p.ip);
        await this.playerTracker.processStatus(status.players);
      }
    } catch (error) {}
  }

  private setupJoinListener(): void {
    this.rconService.onPlayerJoin((player: StatusPlayer) => {
      if (!this.joinListenerActive) return;
      const prevIp = this.playerIpHistory.get(player.id);
      this.playerIpHistory.set(player.id, player.ip);
      if (prevIp === player.ip) return;
      if (this.listManager.isWhitelisted(player.ip) || this.listManager.isPrivateIP(player.ip)) return;
      if (this.cache.get(player.ip)) return;
      this.playerTracker.checkIpForPlayer(player);
    });

    this.rconService.onPlayerLeave((clientId: number) => {
      if (!this.joinListenerActive) return;
      this.playerTracker.checkPlayerOnLeave(clientId);
    });
  }

  private async onDisconnect(reason: string, fromServer: boolean): Promise<void> {
    this.isRunning = false;
    this.joinListenerActive = false;
    if (this.statusInterval) { clearInterval(this.statusInterval); this.statusInterval = null; }
    this.playerIpHistory.clear();
    if (this.reconnectAttempts < this.config.monitoring.max_reconnect_attempts) {
      this.reconnectAttempts++;
      setTimeout(() => this.client.connect().catch(() => {}), this.config.monitoring.reconnect_delay_ms);
    }
  }

  private async checkStatus(): Promise<void> {
    try {
      const status = await this.rconService.executeStatus();
      if (status.players.length > 0) {
        for (const p of status.players) this.playerIpHistory.set(p.id, p.ip);
        await this.playerTracker.processStatus(status.players);
      }
    } catch (error) {}
  }

  async start(): Promise<void> { await this.client.connect(); }

  stop(): void {
    this.isRunning = false;
    this.joinListenerActive = false;
    if (this.statusInterval) { clearInterval(this.statusInterval); this.statusInterval = null; }
    this.playerTracker.clear();
    this.playerIpHistory.clear();
    try { this.client.Disconnect(); } catch (e) {}
  }
}