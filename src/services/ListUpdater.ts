// src/services/ListUpdater.ts
import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { Logger } from '../utils/Logger';
import { ListManager } from './ListManager';

interface ListSource {
  name: string;
  url: string;
  type: 'vpn' | 'datacenter' | 'hosting' | 'cdn' | 'tor' | 'proxy';
  enabled: boolean;
}

export class ListUpdater {
  private static instance: ListUpdater;
  private logger: Logger;
  private listManager: ListManager;
  private updateInterval: NodeJS.Timeout | null = null;
  private dataDir: string;
  private listsDir: string;
  private isUpdating: boolean = false;

  // ТОЛЬКО ПРОВЕРЕННЫЕ РАБОЧИЕ ИСТОЧНИКИ
  private sources: ListSource[] = [
    {
      name: 'X4BNet-VPN',
      url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt',
      type: 'vpn',
      enabled: true
    },
    {
      name: 'X4BNet-Datacenter',
      url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt',
      type: 'datacenter',
      enabled: true
    },
    {
      name: 'ScavengeR-VPN',
      url: 'https://raw.githubusercontent.com/Scav-engeR/vpn_list/main/output/vpn/ipv4.txt',
      type: 'vpn',
      enabled: true
    },
    {
      name: 'ScavengeR-Datacenter',
      url: 'https://raw.githubusercontent.com/Scav-engeR/vpn_list/main/output/datacenter/ipv4.txt',
      type: 'datacenter',
      enabled: true
    },
    {
      name: 'CDN-All',
      url: 'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/all/all_plain_ipv4.txt',
      type: 'hosting',
      enabled: true
    },
    {
      name: 'CDN-Only',
      url: 'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cdn-only/cdn-only_plain_ipv4.txt',
      type: 'cdn',
      enabled: true
    },
    {
      name: 'IPSet-All',
      url: 'https://raw.githubusercontent.com/tn3w/IPSet/main/iplist.txt',
      type: 'vpn',
      enabled: true
    },
    {
      name: 'TOR-Exit-Nodes',
      url: 'https://check.torproject.org/torbulkexitlist',
      type: 'tor',
      enabled: true
    },
    {
      name: 'TheSpeedX-Proxy',
      url: 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
      type: 'proxy',
      enabled: true
    },
    {
      name: 'Datacenter-IPs',
      url: 'https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt',
      type: 'datacenter',
      enabled: true
    }
  ];

  private constructor() {
    this.logger = Logger.getInstance();
    this.listManager = ListManager.getInstance();
    this.dataDir = path.join(process.cwd(), 'data');
    this.listsDir = path.join(this.dataDir, 'lists');
    
    if (!fs.existsSync(this.listsDir)) {
      fs.mkdirSync(this.listsDir, { recursive: true });
    }
  }

  static getInstance(): ListUpdater {
    if (!ListUpdater.instance) {
      ListUpdater.instance = new ListUpdater();
    }
    return ListUpdater.instance;
  }

  startAutoUpdate(intervalHours: number = 6): void {
    const enabledCount = this.sources.filter(s => s.enabled).length;
    this.logger.info(`🔄 Auto-update every ${intervalHours}h from ${enabledCount} sources`);
    
    if (this.updateInterval) clearInterval(this.updateInterval);
    const intervalMs = intervalHours * 60 * 60 * 1000;
    this.updateInterval = setInterval(() => this.updateAllLists(), intervalMs);
  }

  stopAutoUpdate(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  async updateAllLists(): Promise<void> {
    if (this.isUpdating) {
      this.logger.info('📥 Update already in progress, skipping');
      return;
    }
    
    this.isUpdating = true;
    const startTime = Date.now();
    
    const enabledSources = this.sources.filter(s => s.enabled);
    let totalIPs = 0;
    let imported = 0;
    let skipped = 0;
    let ok = 0;
    let fail = 0;

    this.logger.info(`📥 Downloading from ${enabledSources.length} sources...`);

    // Скачиваем пакетами по 5
    for (let i = 0; i < enabledSources.length; i += 5) {
      const batch = enabledSources.slice(i, i + 5);
      const batchResults = await Promise.all(
        batch.map(source => this.downloadList(source).then(ips => {
          if (ips.length > 0) {
            totalIPs += ips.length;
            ok++;
            
            // Сохраняем на диск
            this.saveListToFile(source.name, ips);
            
            // Добавляем в blacklist
            for (const ip of ips) {
              if (this.listManager.isWhitelisted(ip) || this.listManager.isPrivateIP(ip)) {
                skipped++;
                continue;
              }
              if (!this.listManager.isBlacklisted(ip)) {
                this.listManager.addToBlacklist(ip, `List: ${source.name}`, 'Auto-Import');
                imported++;
              } else {
                skipped++;
              }
            }
          } else {
            fail++;
          }
          return { name: source.name, ips };
        }).catch((err) => {
          fail++;
          this.logger.warn(`  ❌ ${source.name}: ${err.message}`);
          return { name: source.name, ips: [] };
        }))
      );
      
      if (i + 5 < enabledSources.length) {
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    this.logger.info(`📥 Done: ${totalIPs} IPs, ${imported} new, ${skipped} skipped, ${ok}/${enabledSources.length} ok, ${fail} fail (${duration}s)`);
    
    // Сохраняем метаданные
    const metadata = {
      last_update: new Date().toISOString(),
      total_ips: totalIPs,
      imported,
      skipped,
      sources_ok: ok,
      sources_fail: fail
    };
    fs.writeFileSync(
      path.join(this.listsDir, 'update_metadata.json'),
      JSON.stringify(metadata, null, 2),
      'utf-8'
    );
    
    this.isUpdating = false;
  }

  private async downloadList(source: ListSource): Promise<string[]> {
    const response = await axios.get(source.url, {
      timeout: 15000,
      responseType: 'text',
      headers: { 'User-Agent': 'LythorixAntiVpn/2.0' },
      validateStatus: (status) => status < 500
    });
    
    if (response.status === 404) {
      this.logger.warn(`    ⚠️ ${source.name}: 404 not found`);
      return [];
    }

    const lines = (response.data as string).split('\n');
    const ips: string[] = [];
    
    for (const line of lines) {
      const t = line.trim();
      if (!t || t.startsWith('#') || t.startsWith('//')) continue;
      const m = t.match(/(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/);
      if (m) ips.push(m[0]);
    }
    
    return [...new Set(ips)];
  }

  private saveListToFile(name: string, ips: string[]): void {
    const filename = name.toLowerCase().replace(/[^a-z0-9]/g, '_') + '.txt';
    const filepath = path.join(this.listsDir, filename);
    fs.writeFileSync(filepath, ips.join('\n'), 'utf-8');
  }

  loadListsFromDisk(): void {
    if (!fs.existsSync(this.listsDir)) return;
    
    const files = fs.readdirSync(this.listsDir).filter(f => f.endsWith('.txt'));
    if (files.length === 0) {
      this.logger.info('📂 No local lists found');
      return;
    }
    
    let totalIPs = 0;
    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(this.listsDir, file), 'utf-8');
        totalIPs += content.split('\n').filter(l => l.trim() && !l.startsWith('#')).length;
      } catch {}
    }
    
    this.logger.info(`📂 ${totalIPs} IPs on disk in ${files.length} files`);
  }

  getStats() {
    return {
      total_sources: this.sources.length,
      enabled_sources: this.sources.filter(s => s.enabled).length,
      is_updating: this.isUpdating,
      lists_dir: this.listsDir
    };
  }
}