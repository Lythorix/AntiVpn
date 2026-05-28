// src/services/WebhookService.ts
import axios, { AxiosInstance } from 'axios';
import { AlertPayload, IpCheckResult, TrackedPlayer } from '../types';
import { Logger } from '../utils/Logger';
import { ConfigManager } from '../config/ConfigManager';

export class WebhookService {
  private static instance: WebhookService;
  private mainWebhook: AxiosInstance;
  private alertWebhook: AxiosInstance | null = null;
  private logger: Logger;
  private alertQueue: AlertPayload[] = [];
  private flushInterval: NodeJS.Timeout | null = null;
  private serverAddress: string;
  private mode: string;
  private autoBanEnabled: boolean;

  private constructor(mainUrl: string, alertUrl?: string) {
    this.logger = Logger.getInstance();
    
    try {
      const config = ConfigManager.getInstance().getAll();
      this.serverAddress = `${config.server.host}:${config.server.port}`;
      this.mode = config.auto_ban?.mode || 'warn';
      this.autoBanEnabled = config.auto_ban?.enabled || false;
    } catch {
      this.serverAddress = 'Unknown';
      this.mode = 'warn';
      this.autoBanEnabled = false;
    }
    
    this.mainWebhook = axios.create({
      baseURL: mainUrl,
      timeout: 10000,
      headers: { 'Content-Type': 'application/json' }
    });

    if (alertUrl) {
      this.alertWebhook = axios.create({
        baseURL: alertUrl,
        timeout: 10000,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    this.flushInterval = setInterval(() => this.flushAlerts(), 30000);
  }

  static getInstance(mainUrl?: string, alertUrl?: string): WebhookService {
    if (!WebhookService.instance) {
      if (!mainUrl) throw new Error('Main webhook URL required');
      WebhookService.instance = new WebhookService(mainUrl, alertUrl);
    }
    return WebhookService.instance;
  }

  async sendInfo(title: string, description: string, fields?: Array<{name: string; value: string; inline?: boolean}>): Promise<void> {
    await this.sendEmbed(this.mainWebhook, {
      color: 0x3498db,
      title,
      description,
      fields,
      timestamp: new Date().toISOString(),
      footer: { text: `LythorixAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    });
  }

  async sendWarning(title: string, description: string, fields?: Array<{name: string; value: string; inline?: boolean}>): Promise<void> {
    await this.sendEmbed(this.mainWebhook, {
      color: 0xf1c40f,
      title: `⚠️ ${title}`,
      description,
      fields,
      timestamp: new Date().toISOString(),
      footer: { text: `LythorixAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    });
  }

  async sendError(title: string, description: string, fields?: Array<{name: string; value: string; inline?: boolean}>): Promise<void> {
    await this.sendEmbed(this.mainWebhook, {
      color: 0xe74c3c,
      title: `❌ ${title}`,
      description,
      fields,
      timestamp: new Date().toISOString(),
      footer: { text: `LythorixAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    });
  }

  async sendAlert(alert: AlertPayload): Promise<void> {
    this.alertQueue.push(alert);
    if (alert.severity === 'critical') await this.flushAlerts();
  }

  async sendVpnDetectionAlert(player: TrackedPlayer, ipCheck: IpCheckResult): Promise<void> {
    const detectionType = this.getDetectionType(ipCheck);
    
    const colorMap: Record<string, number> = {
      'critical': 0x992d22, 'high': 0xe74c3c, 'medium': 0xf1c40f, 'low': 0x3498db
    };

    const threatEmoji: Record<string, string> = {
      'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'
    };

    const embed = {
      color: colorMap[ipCheck.threat_level || 'low'] || 0xe74c3c,
      author: {
        name: `🛡️ LythorixAntiVpn v2.0.0`,
        icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      },
      title: `🚨 ${detectionType} DETECTED`,
      description: 
        '```yaml\n' +
        `🚨 ${detectionType}\n` +
        `   ├─ Nick: ${player.nickname}\n` +
        `   ├─ ID: ${player.id}  |  Clan: ${player.clan || 'None'}\n` +
        `   ├─ IP: ${player.ip}\n` +
        `   ├─ Country: ${ipCheck.country || 'Unknown'}\n` +
        `   ├─ City: ${ipCheck.city || 'Unknown'}\n` +
        `   ├─ ISP: ${ipCheck.isp || 'Unknown'}\n` +
        `   ├─ Org: ${ipCheck.organization || 'Unknown'}\n` +
        `   ├─ Risk Score: ${ipCheck.risk_score || 0}/100\n` +
        `   ├─ Threat: ${(ipCheck.threat_level || 'low').toUpperCase()}\n` +
        `   └─ Whitelist: ${player.flags.is_whitelisted ? '✅' : '❌'} | Blacklist: ${player.flags.is_blacklisted ? '✅' : '❌'}\n` +
        '```',
      fields: [
        { name: '👤 Nickname', value: `\`${player.nickname}\``, inline: true },
        { name: '🆔 ID', value: String(player.id), inline: true },
        { name: '🏠 Clan', value: player.clan || 'None', inline: true },
        { name: '🌐 IP', value: `\`${player.ip}\``, inline: true },
        { name: '🌍 Country', value: ipCheck.country || 'Unknown', inline: true },
        { name: '🏙️ City', value: ipCheck.city || 'Unknown', inline: true },
        { name: '📡 ISP', value: ipCheck.isp || 'Unknown', inline: true },
        { name: '🏢 Organization', value: ipCheck.organization || 'Unknown', inline: true },
        { name: '🛡️ Risk Score', value: `${ipCheck.risk_score || 0}/100`, inline: true },
        { name: `${threatEmoji[ipCheck.threat_level || 'low']} Threat`, value: (ipCheck.threat_level || 'low').toUpperCase(), inline: true },
        { name: '🔍 Detection', value: detectionType, inline: true },
        { 
          name: '🔍 Details', 
          value: [
            `VPN: ${ipCheck.is_vpn ? '✅ YES' : '❌ No'}`,
            `Proxy: ${ipCheck.is_proxy ? '✅ YES' : '❌ No'}`,
            `TOR: ${ipCheck.is_tor ? '✅ YES' : '❌ No'}`,
            `Hosting: ${ipCheck.is_hosting ? '✅ YES' : '❌ No'}`,
            `Datacenter: ${ipCheck.is_datacenter ? '✅ YES' : '❌ No'}`
          ].join(' | '),
          inline: false 
        },
        { name: '🛡️ Whitelist', value: player.flags.is_whitelisted ? '✅' : '❌', inline: true },
        { name: '⛔ Blacklist', value: player.flags.is_blacklisted ? '✅' : '❌', inline: true },
        { name: '⏰ Time', value: new Date().toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' }), inline: true },
        { name: '🌐 Server', value: `\`${this.serverAddress}\``, inline: true },
        { name: '🔧 Mode', value: `${this.mode.toUpperCase()} | AutoBan: ${this.autoBanEnabled ? 'ON' : 'OFF'}`, inline: true }
      ],
      thumbnail: { url: 'https://ibb.co/gZ5CnMGv' },
      timestamp: new Date().toISOString(),
      footer: { text: `LythorixAntiVpn • ${this.serverAddress} • ${this.mode.toUpperCase()}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    const targetWebhook = this.alertWebhook || this.mainWebhook;
    await this.sendEmbed(targetWebhook, embed);
    this.logger.info(`📤 Alert sent for ${player.nickname}`);
  }

  async sendCleanPlayerInfo(player: TrackedPlayer, ipCheck: IpCheckResult): Promise<void> {
    const time = new Date().toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' });
    
    const embed = {
      color: 0x2ecc71,
      author: {
        name: `🛡️ LythorixAntiVpn v2.0.0`,
        icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      },
      title: `✅ Clean: ${player.nickname}`,
      description:
        '```yaml\n' +
        `✅ CLEAN | ${time}\n` +
        `   ├─ Nick: ${player.nickname}\n` +
        `   ├─ ID: ${player.id}  |  Clan: ${player.clan || 'None'}\n` +
        `   ├─ IP: ${player.ip}\n` +
        `   ├─ Country: ${ipCheck.country || 'Unknown'}\n` +
        `   ├─ City: ${ipCheck.city || 'Unknown'}\n` +
        `   ├─ ISP: ${ipCheck.isp || 'Unknown'}\n` +
        `   └─ Score: ${ipCheck.risk_score || 0}/100\n` +
        '```',
      fields: [
        { name: '👤 Nickname', value: player.nickname, inline: true },
        { name: '🆔 ID', value: String(player.id), inline: true },
        { name: '🏠 Clan', value: player.clan || 'None', inline: true },
        { name: '🌐 IP', value: `\`${player.ip}\``, inline: true },
        { name: '🌍 Country', value: ipCheck.country || 'Unknown', inline: true },
        { name: '🏙️ City', value: ipCheck.city || 'Unknown', inline: true },
        { name: '📡 ISP', value: ipCheck.isp || 'Unknown', inline: true },
        { name: '🏢 Organization', value: ipCheck.organization || 'Unknown', inline: true },
        { name: '🛡️ Risk Score', value: `${ipCheck.risk_score || 0}/100`, inline: true },
        { name: '✅ Status', value: 'CLEAN', inline: true },
        { name: '🌐 Server', value: `\`${this.serverAddress}\``, inline: true }
      ],
      timestamp: new Date().toISOString(),
      footer: { text: `LythorixAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    const targetWebhook = this.alertWebhook || this.mainWebhook;
    await this.sendEmbed(targetWebhook, embed);
  }

  async sendStartupMessage(config: { server: string; whitelist: number; blacklist: number }): Promise<void> {
    const modeColor = this.mode === 'autoban' ? '🔴' : '🟡';
    
    const embed = {
      color: 0x5865f2,
      author: {
        name: `🛡️ LythorixAntiVpn v2.0.0`,
        icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      },
      title: '🟢 Bot Started',
      description:
      '```\n' +
     '╔══════════════════════════════════════╗\n' +
     '║                                                 ║\n' +
     '║  🛡️  LythorixAntiVpn  v2.0.0                   ║\n' +
     '║  DDNet Anti-Abuse Security System               ║\n' +
     '║                                                 ║\n' +
     '╚══════════════════════════════════════╝\n' +
     '```\n' +
        `🌐 **Server:** \`${this.serverAddress}\`\n` +
        `${modeColor} **Mode:** ${this.mode.toUpperCase()}\n` +
        `🔨 **AutoBan:** ${this.autoBanEnabled ? 'ON' : 'OFF'}\n` +
        `✅ **Whitelist:** ${config.whitelist} IPs\n` +
        `⛔ **Blacklist:** ${config.blacklist} IPs\n\n` +
        `👁️ **Monitoring started**`,
      thumbnail: { url: 'https://ibb.co/gZ5CnMGv' },
      timestamp: new Date().toISOString(),
      footer: { text: `LythorixAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    await this.sendEmbed(this.mainWebhook, embed);
  }

  async sendAutoBan(player: TrackedPlayer, ipCheck: IpCheckResult): Promise<void> {
    const embed = {
      color: 0xe74c3c,
      title: '🔨 Auto-Ban',
      description:
        '```yaml\n' +
        `🔨 BANNED\n` +
        `   ├─ Nick: ${player.nickname}\n` +
        `   ├─ ID: ${player.id}\n` +
        `   ├─ IP: ${player.ip}\n` +
        `   └─ Score: ${ipCheck.risk_score || 0}/100\n` +
        '```',
      fields: [
        { name: '👤 Player', value: player.nickname, inline: true },
        { name: '🆔 ID', value: String(player.id), inline: true },
        { name: '🌐 IP', value: `\`${player.ip}\``, inline: true },
        { name: '📡 ISP', value: ipCheck.isp || 'Unknown', inline: true },
        { name: '🛡️ Score', value: `${ipCheck.risk_score || 0}/100`, inline: true },
        { name: '🔧 Mode', value: 'AUTOBAN', inline: true },
        { name: '🌐 Server', value: `\`${this.serverAddress}\``, inline: true }
      ],
      timestamp: new Date().toISOString(),
      footer: { text: `LythorixAntiVpn • ${this.serverAddress} • AUTOBAN`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    await this.sendEmbed(this.mainWebhook, embed);
  }

  private async sendEmbed(webhook: AxiosInstance, embed: any): Promise<void> {
    try {
      await webhook.post('', {
        embeds: [embed],
        username: 'LythorixAntiVpn',
        avatar_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      });
    } catch (error: any) {
      this.logger.error('Webhook failed', { status: error.response?.status });
    }
  }

  private getDetectionType(ipCheck: IpCheckResult): string {
    const types: string[] = [];
    if (ipCheck.is_datacenter) types.push('🏢 DATACENTER');
    if (ipCheck.is_vpn) types.push('🔒 VPN');
    if (ipCheck.is_proxy) types.push('🔄 PROXY');
    if (ipCheck.is_tor) types.push('🧅 TOR');
    if (ipCheck.is_hosting) types.push('🖥️ HOSTING');
    return types.join(' | ') || '⚠️ UNKNOWN';
  }

  private async flushAlerts(): Promise<void> {
    if (this.alertQueue.length === 0) return;
    const alerts = [...this.alertQueue];
    this.alertQueue = [];
    for (const alert of alerts) {
      try { await this.sendAlertEmbed(alert); await this.delay(500); } catch (e) {}
    }
  }

  private async sendAlertEmbed(alert: AlertPayload): Promise<void> {
    const colorMap: Record<string, number> = { 'info': 0x3498db, 'warning': 0xf1c40f, 'critical': 0xe74c3c };
    const embed = {
      color: colorMap[alert.severity],
      title: alert.type.toUpperCase(),
      fields: [
        ...(alert.player ? [
          { name: 'Player', value: alert.player.nickname, inline: true },
          { name: 'IP', value: `\`${alert.player.ip}\``, inline: true }
        ] : []),
        { name: 'Server', value: `\`${this.serverAddress}\``, inline: true }
      ],
      timestamp: alert.timestamp,
      footer: { text: `LythorixAntiVpn • ${this.serverAddress}` }
    };

    await this.sendEmbed(this.alertWebhook || this.mainWebhook, embed);
  }

  private delay(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

  destroy(): void {
    if (this.flushInterval) clearInterval(this.flushInterval);
    this.flushAlerts();
  }
}