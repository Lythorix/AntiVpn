// src/core/SessionManager.ts - ORIGINAL
import { Logger } from '../utils/Logger';
import { RconService } from '../services/RconService';
import { WebhookService } from '../services/WebhookService';
import { PlayerTracker } from './PlayerTracker';
import { ListManager } from '../services/ListManager';
import { CacheService } from '../utils/Cache';
import { LogCleaner } from '../utils/LogCleaner';
import { AppConfig, StatusPlayer } from '../types';

// Session manager - handles connection lifecycle and monitoring
export class SessionManager {
  private client: any;
  private config: AppConfig;
  private logger: Logger;
  private rconService: RconService;
  private webhookService: WebhookService;
  private playerTracker: PlayerTracker;
  private listManager: ListManager;
  private cache: CacheService;
  private logCleaner: LogCleaner;
  private isRunning: boolean = false;
  private reconnectAttempts: number = 0;
  private statusInterval: NodeJS.Timeout | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private hourlyReconnectTimer: NodeJS.Timeout | null = null;
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
    this.logCleaner = LogCleaner.getInstance();
    
    this.setupEventListeners();
  }

  private setupEventListeners(): void {
    this.client.on('connected', () => this.onConnected());
    this.client.on('disconnect', (reason: string, fromServer: boolean) => this.onDisconnect(reason, fromServer));
  }

  private async onConnected(): Promise<void> {
    this.reconnectAttempts = 0;
    this.isRunning = true;
    this.playerIpHistory.clear();
    this.joinListenerActive = false;
    
    try {
      // Set spectator mode
      this.client.game.SetTeam(-1);
      
      // Login to RCON
      await this.rconService.login(this.config.server.rcon_password, this.config.server.rcon_username);
      this.playerTracker.setRconService(this.rconService);

      // Configure server for IP visibility
      await this.rconService.execute('hide_auth_status 1');
      await this.rconService.execute('show_ips 1');

      // Send startup notification
      const ws = this.listManager.getWhitelistStats();
      const bs = this.listManager.getBlacklistStats();
      await this.webhookService.sendStartupMessage({ 
        server: `${this.config.server.host}:${this.config.server.port}`, 
        whitelist: ws.ips, 
        blacklist: bs.ips 
      });

      // Initial status check
      await this.initialStatusCheck();
      
      // Setup player join/leave listener
      this.setupJoinListener();
      this.joinListenerActive = true;
      
      // Start periodic status checking
      this.statusInterval = setInterval(() => this.checkStatus(), this.config.monitoring.status_interval_seconds * 1000);
      
      // Start hourly reconnect if enabled
      if (this.config.monitoring.hourly_reconnect) {
        this.setupHourlyReconnect();
      }
      
      this.logger.info('Session ready');
    } catch (error) {
      this.logger.error('Connection initialization failed', error);
    }
  }

  private setupHourlyReconnect(): void {
    const intervalMinutes = this.config.monitoring.reconnect_interval_minutes || 60;
    const intervalMs = intervalMinutes * 60 * 1000;
    
    this.logger.info(`Hourly reconnect scheduled every ${intervalMinutes} minutes`);
    
    this.hourlyReconnectTimer = setInterval(async () => {
      this.logger.info('Performing scheduled reconnect...');
      
      // Save state before disconnect
      this.cache.saveToDisk();
      
      // Disconnect
      try {
        if (this.client) {
          this.client.Disconnect();
        }
      } catch (e) {}
      
      // Wait before reconnecting
      await this.delay(3000);
      
      // Reconnect
      try {
        await this.client.connect();
        this.logger.info('Scheduled reconnect successful');
      } catch (error) {
        this.logger.error('Scheduled reconnect failed', error);
      }
    }, intervalMs);
  }

  private async onDisconnect(reason: string, fromServer: boolean): Promise<void> {
    this.isRunning = false;
    this.joinListenerActive = false;
    
    if (this.statusInterval) {
      clearInterval(this.statusInterval);
      this.statusInterval = null;
    }
    
    this.playerIpHistory.clear();
    
    // Attempt reconnection
    if (this.reconnectAttempts < this.config.monitoring.max_reconnect_attempts) {
      this.reconnectAttempts++;
      
      // Exponential backoff delay
      const delay = Math.min(
        this.config.monitoring.reconnect_delay_ms * Math.pow(1.5, this.reconnectAttempts),
        30000
      );
      
      this.logger.info(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.config.monitoring.max_reconnect_attempts})`);
      
      this.reconnectTimer = setTimeout(() => {
        this.client.connect().catch(() => {});
      }, delay);
    } else {
      this.logger.error('Max reconnect attempts reached');
    }
  }

  private async initialStatusCheck(): Promise<void> {
    try {
      const status = await this.rconService.executeStatus();
      if (status.players.length > 0) {
        for (const p of status.players) {
          this.playerIpHistory.set(p.id, p.ip);
        }
        await this.playerTracker.processStatus(status.players);
      }
    } catch (error) {
      this.logger.warn('Initial status check failed', error);
    }
  }

  private setupJoinListener(): void {
    // Handle player join events
    this.rconService.onPlayerJoin((player: StatusPlayer) => {
      if (!this.joinListenerActive) return;
      if (player.nickname === this.config.bot.nickname) return;
      
      const prevIp = this.playerIpHistory.get(player.id);
      this.playerIpHistory.set(player.id, player.ip);
      
      // Skip re-check for same IP
      if (prevIp === player.ip) return;
      if (this.listManager.isPrivateIP(player.ip)) return;
      
      // Check IP immediately on join
      this.playerTracker.checkIpForPlayer(player);
    });

    // Handle player leave events
    this.rconService.onPlayerLeave((clientId: number) => {
      if (!this.joinListenerActive) return;
      this.playerTracker.checkPlayerOnLeave(clientId);
    });
  }

  private async checkStatus(): Promise<void> {
    if (!this.isRunning) return;
    
    try {
      const status = await this.rconService.executeStatus();
      if (status.players.length > 0) {
        for (const p of status.players) {
          this.playerIpHistory.set(p.id, p.ip);
        }
        await this.playerTracker.processStatus(status.players);
      }
    } catch (error) {
      this.logger.warn('Status check failed', error);
    }
  }

  async start(): Promise<void> {
    await this.client.connect();
  }

  stop(): void {
    this.isRunning = false;
    this.joinListenerActive = false;
    
    // Clear all timers
    if (this.statusInterval) {
      clearInterval(this.statusInterval);
      this.statusInterval = null;
    }
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    
    if (this.hourlyReconnectTimer) {
      clearInterval(this.hourlyReconnectTimer);
      this.hourlyReconnectTimer = null;
    }
    
    // Clear state
    this.playerTracker.clear();
    this.playerIpHistory.clear();
    
    try {
      if (this.client) {
        this.client.Disconnect();
      }
    } catch (e) {}
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}