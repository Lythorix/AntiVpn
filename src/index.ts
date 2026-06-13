// src/index.ts - Updated with cache support
import { ConfigManager } from './config/ConfigManager';
import { Logger } from './utils/Logger';
import { CacheService } from './utils/Cache';
import { ListManager } from './services/ListManager';
import { ListUpdater } from './services/ListUpdater';
import { IpChecker } from './services/IpChecker';
import { WebhookService } from './services/WebhookService';
import { SessionManager } from './core/SessionManager';
import { QueueSystem } from './utils/Queue';
import { PlayerTracker } from './core/PlayerTracker';
import { LogCleaner } from './utils/LogCleaner';
import { AppConfig } from './types';
import * as path from 'path';
import * as fs from 'fs';

const Teeworlds = require('teeworlds');

// Console colors for pretty output
const c = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  dim: '\x1b[2m',
};

// Main bot class
class LythorixAntiVpn {
  private client: any;
  private configManager: ConfigManager;
  private logger: Logger;
  private sessionManager!: SessionManager;
  private listUpdater!: ListUpdater;
  private logCleaner!: LogCleaner;
  private config!: AppConfig;
  private isShuttingDown: boolean = false;

  constructor() {
    this.logger = Logger.getInstance();
    this.configManager = ConfigManager.getInstance();
  }

  private printBanner(): void {
    const mode = this.config.auto_ban?.mode || 'warn';
    const enabled = this.config.auto_ban?.enabled ? 'ON' : 'OFF';
    const hourlyReconnect = this.config.monitoring?.hourly_reconnect ? 'ON' : 'OFF';
    const modeColor = mode === 'autoban' ? c.red : c.yellow;
    const enabledColor = enabled === 'ON' && mode === 'autoban' ? c.red : c.green;

    console.log('\n');
    console.log(`${c.cyan}${c.bright}╔══════════════════════════════════════════════════╗${c.reset}`);
    console.log(`${c.cyan}${c.bright}║                                                  ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║     ${c.white}LythorixAntiVpn v2.0.0${c.cyan}                     ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║     ${c.dim}DDNet Anti-Abuse Security System${c.cyan}               ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║                                                  ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}╚══════════════════════════════════════════════════╝${c.reset}`);
    console.log('');
    console.log(`${c.green}  Target: ${c.white}${this.config.server.host}:${this.config.server.port}${c.reset}`);
    console.log(`${c.green}  Bot: ${c.white}${this.config.bot.nickname}${c.reset}`);
    console.log(`${c.green}  Client: ${c.white}DDNet 67${c.reset}`);
    console.log(`${c.green}  Mode: ${modeColor}${mode.toUpperCase()}${c.reset} ${c.dim}|${c.reset} AutoBan: ${enabledColor}${enabled}${c.reset}`);
    console.log(`${c.green}  Hourly Reconnect: ${c.white}${hourlyReconnect}${c.reset}`);
    console.log(`${c.green}  Interval: ${c.white}${this.config.monitoring.status_interval_seconds}s${c.reset}`);
    console.log('');
  }

  private async loadCustomBlacklists(): Promise<void> {
    const listManager = ListManager.getInstance();
    
    const blacklistFiles = [
      path.join(process.cwd(), 'blacklist.txt'),
      path.join(process.cwd(), 'data', 'custom_blacklist.txt'),
      path.join(process.cwd(), 'data', 'manual_blacklist.txt')
    ];
    
    let totalLoaded = 0;
    
    for (const file of blacklistFiles) {
      if (fs.existsSync(file)) {
        console.log(`${c.dim}  Loading: ${file}${c.reset}`);
        const loaded = await listManager.loadCustomBlacklist(file);
        totalLoaded += loaded;
        if (loaded > 0) {
          console.log(`${c.green}    +${loaded} IPs loaded${c.reset}`);
        }
      }
    }
    
    if (totalLoaded > 0) {
      console.log(`${c.green}  Total custom blacklist IPs loaded: ${totalLoaded}${c.reset}`);
    }
  }

  private async initializeServices(): Promise<void> {
    // 1. Load configuration
    this.config = this.configManager.load();
    
    this.printBanner();

    // 2. Initialize base services
    WebhookService.getInstance(this.config.discord.webhook_url, this.config.discord.alert_webhook_url);
    
    const cache = CacheService.getInstance();
    if (this.config.ipcheck?.cache_ttl_hours) {
      cache.setTTL(this.config.ipcheck.cache_ttl_hours);
    }
    
    QueueSystem.getInstance();
    PlayerTracker.getInstance();
    this.logCleaner = LogCleaner.getInstance();
    this.logCleaner.startAutoCleanup();

    // 3. Initialize ListManager
    const listManager = ListManager.getInstance();
    
    console.log('');
    console.log(`${c.yellow}  ══════════════════════════════════════════════════${c.reset}`);
    console.log(`${c.cyan}  📥 PHASE 1: Loading lists from disk...${c.reset}`);
    
    const blStats = listManager.getBlacklistStats();
    const wlStats = listManager.getWhitelistStats();
    
    console.log(`${c.green}    Blacklist: ${c.white}${blStats.ips} IPs loaded from data/blacklist.json${c.reset}`);
    console.log(`${c.green}    Whitelist: ${c.white}${wlStats.ips} IPs loaded from data/whitelist.json${c.reset}`);
    
    await this.loadCustomBlacklists();
    
    // Initialize ListUpdater
    this.listUpdater = ListUpdater.getInstance();
    
    console.log('');
    console.log(`${c.cyan}  🌐 PHASE 2: Checking for updates from external sources...${c.reset}`);
    console.log(`${c.dim}    (Incremental mode: only new IPs will be added)${c.reset}`);
    
    // Download only new/changed IPs
    await this.listUpdater.updateAllLists(true);
    
    // Start auto-update (every 6 hours, incremental)
    this.listUpdater.startAutoUpdate(6);
    
    console.log('');
    console.log(`${c.green}  ✅ PHASE 3: All lists ready!${c.reset}`);
    
    // Print final statistics
    const finalBlStats = listManager.getBlacklistStats();
    const finalWlStats = listManager.getWhitelistStats();
    const stats = this.listUpdater.getStats();
    const logStats = this.logCleaner.getLogStats();
    
    console.log('');
    console.log(`${c.green}  📊 Final Statistics:${c.reset}`);
    console.log(`${c.green}     External sources: ${c.white}${stats.enabled_sources}/${stats.total_sources} sources${c.reset}`);
    console.log(`${c.green}     Cached sources: ${c.white}${stats.cached_sources}${c.reset}`);
    console.log(`${c.green}     Blacklist total: ${c.white}${finalBlStats.ips} IPs (${finalBlStats.auto_added} auto)${c.reset}`);
    console.log(`${c.green}     Whitelist total: ${c.white}${finalWlStats.ips} IPs, ${finalWlStats.providers} providers${c.reset}`);
    console.log(`${c.green}     Logs: ${c.white}${logStats.totalFiles} files, ${(logStats.totalSize / 1024).toFixed(1)}KB${c.reset}`);
    console.log('');
    
    // 4. Initialize IpChecker with config
    IpChecker.getInstance(this.config);
    
    // 5. Create Teeworlds client
    this.client = new Teeworlds.Client(
      this.config.server.host,
      this.config.server.port,
      this.config.bot.nickname,
      {
        identity: {
          name: this.config.bot.nickname,
          clan: this.config.bot.clan || 'Security',
          country: -1,
          skin: 'default',
          use_custom_color: 1,
          color_body: 10346103,
          color_feet: 65535
        },
        ddnet_version: {
          version: 67,
          release_version: '67'
        },
        NET_VERSION: '0.6 626fce9a778df4d4'
      }
    );
  }

  async start(): Promise<void> {
    console.log(`${c.yellow}  🚀 Starting LythorixAntiVpn...${c.reset}\n`);
    
    try {
      await this.initializeServices();
      
      console.log(`${c.green}  🔌 Connecting to server...${c.reset}\n`);
      
      this.sessionManager = new SessionManager(this.client, this.config);
      await this.sessionManager.start();
      
      console.log(`${c.green}  ✅ Bot is running!${c.reset}\n`);
    } catch (error) {
      this.logger.error('Failed to start bot', error);
      console.log(`${c.red}  ❌ Failed to start: ${(error as Error).message}${c.reset}`);
      process.exit(1);
    }
  }

  async stop(): Promise<void> {
    if (this.isShuttingDown) return;
    this.isShuttingDown = true;
    
    console.log(`\n${c.yellow}  🛑 Shutting down...${c.reset}`);
    
    if (this.listUpdater) {
      this.listUpdater.stopAutoUpdate();
    }
    
    if (this.logCleaner) {
      this.logCleaner.stopAutoCleanup();
    }
    
    if (this.sessionManager) {
      this.sessionManager.stop();
    }
    
    CacheService.getInstance().saveToDisk();
    
    console.log(`${c.green}  ✅ Shutdown complete${c.reset}\n`);
  }
}

// Graceful shutdown handlers
let bot: LythorixAntiVpn;

const shutdown = async (signal: string) => {
  console.log(`\n${c.yellow}  Received ${signal}, shutting down...${c.reset}`);
  if (bot) await bot.stop();
  process.exit(0);
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('uncaughtException', (error) => {
  console.error(`${c.red}  Uncaught exception:${c.reset}`, error.message);
  console.error(error.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason: any) => {
  console.error(`${c.red}  Unhandled rejection:${c.reset}`, reason?.message || reason);
  process.exit(1);
});

// Start the bot
(async () => {
  bot = new LythorixAntiVpn();
  await bot.start();
})();