// src/index.ts
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

const Teeworlds = require('teeworlds');

// Цвета консоли
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

class LythorixAntiVpn {
  private client: any;
  private configManager: ConfigManager;
  private logger: Logger;
  private sessionManager!: SessionManager;
  private listUpdater!: ListUpdater;

  constructor() {
    this.logger = Logger.getInstance();
    this.configManager = ConfigManager.getInstance();
    const config = this.configManager.load();

    this.printBanner(config);

    // Инициализация сервисов
    WebhookService.getInstance(config.discord.webhook_url, config.discord.alert_webhook_url);
    IpChecker.getInstance(config);
    ListManager.getInstance();
    CacheService.getInstance();
    QueueSystem.getInstance();
    PlayerTracker.getInstance();

    // Инициализация ListUpdater
    this.listUpdater = ListUpdater.getInstance();
    
    // Сначала загружаем списки из локальных файлов (быстрый старт)
    this.listUpdater.loadListsFromDisk();
    
    // Затем запускаем автообновление каждые 6 часов
    this.listUpdater.startAutoUpdate(6);
    
    // Выводим статистику загруженных списков
    const stats = this.listUpdater.getStats();
    const listManager = ListManager.getInstance();
    const blStats = listManager.getBlacklistStats();
    const wlStats = listManager.getWhitelistStats();
    
    console.log(`${c.green}  📋 Lists loaded: ${c.white}${blStats.ips} blacklisted, ${wlStats.ips} whitelisted${c.reset}`);
    console.log(`${c.green}  📡 Sources: ${c.white}${stats.enabled_sources}/${stats.total_sources} enabled${c.reset}`);
    console.log('');

    // Создаем клиент с версией 19020+
    this.client = new Teeworlds.Client(
      config.server.host,
      config.server.port,
      config.bot.nickname,
      {
        identity: {
          name: config.bot.nickname,
          clan: config.bot.clan || 'Security',
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

    this.sessionManager = new SessionManager(this.client, config);
  }

  private printBanner(config: any): void {
    const mode = config.auto_ban?.mode || 'warn';
    const enabled = config.auto_ban?.enabled ? 'ON' : 'OFF';
    const modeColor = mode === 'autoban' ? c.red : c.yellow;
    const enabledColor = enabled === 'ON' && mode === 'autoban' ? c.red : c.green;

    console.log('\n');
    console.log(`${c.cyan}${c.bright}╔══════════════════════════════════════════════════╗${c.reset}`);
    console.log(`${c.cyan}${c.bright}║                                                  ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║     ${c.white}🛡️  LythorixAntiVpn v2.0.0${c.cyan}                     ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║     ${c.dim}DDNet Anti-Abuse Security System${c.cyan}               ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║                                                  ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}╚══════════════════════════════════════════════════╝${c.reset}`);
    console.log('');
    console.log(`${c.green}  🌐 Target: ${c.white}${config.server.host}:${config.server.port}${c.reset}`);
    console.log(`${c.green}  🤖 Bot: ${c.white}${config.bot.nickname}${c.reset}`);
    console.log(`${c.green}  📦 Client: ${c.white}DDNet 67 (67)${c.reset}`);
    console.log(`${c.green}  🔧 Mode: ${modeColor}${mode.toUpperCase()}${c.reset} ${c.dim}|${c.reset} 🔨 AutoBan: ${enabledColor}${enabled}${c.reset}`);
    console.log(`${c.green}  ⏱️  Interval: ${c.white}${config.monitoring.status_interval_seconds}s${c.reset}`);
    console.log('');
    console.log(`${c.dim}  ─────────────────────────────────────────────${c.reset}`);
    console.log('');
  }

  async start(): Promise<void> {
    console.log(`${c.yellow}  🚀 Starting...${c.reset}\n`);
    await this.sessionManager.start();
  }

  async stop(): Promise<void> {
    this.listUpdater.stopAutoUpdate();
    this.sessionManager.stop();
    console.log(`\n${c.red}  👋 LythorixAntiVpn shutdown${c.reset}\n`);
  }
}

// Graceful shutdown
process.on('SIGINT', () => {
  console.log(`\n${c.yellow}  🛑 Shutting down...${c.reset}`);
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log(`\n${c.yellow}  🛑 Shutting down...${c.reset}`);
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error(`${c.red}  ❌ Uncaught exception:${c.reset}`, error.message);
});

process.on('unhandledRejection', (reason: any) => {
  console.error(`${c.red}  ❌ Unhandled rejection:${c.reset}`, reason?.message || reason);
});

// Запуск
const bot = new LythorixAntiVpn();
bot.start().catch((error) => {
  console.error(`${c.red}  ❌ Fatal error:${c.reset}`, error.message);
  process.exit(1);
});