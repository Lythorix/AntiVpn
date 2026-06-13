// src/services/ListUpdater.ts - with caching and incremental updates
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
  etag?: string;
  lastModified?: string;
  lastHash?: string;
}

interface UpdateMetadata {
  last_update: string;
  total_ips: number;
  imported: number;
  skipped: number;
  sources_ok: number;
  sources_fail: number;
  duration_seconds: number;
  incremental: boolean;
}

interface SourceCache {
  name: string;
  hash: string;
  ips: string[];
  lastUpdated: string;
  ipCount: number;
}

// List updater - downloads and updates IP lists with caching - singleton pattern
export class ListUpdater {
  private static instance: ListUpdater;
  private logger: Logger;
  private listManager: ListManager;
  private updateInterval: NodeJS.Timeout | null = null;
  private dataDir: string;
  private listsDir: string;
  private cacheDir: string;
  private isUpdating: boolean = false;
  private metadata: UpdateMetadata | null = null;
  private sourceCache: Map<string, SourceCache> = new Map();

  // Verified working list sources
  private sources: ListSource[] = [
    { name: 'X4BNet-VPN', url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt', type: 'vpn', enabled: true },
    { name: 'X4BNet-Datacenter', url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt', type: 'datacenter', enabled: true },
    { name: 'ScavengeR-VPN', url: 'https://raw.githubusercontent.com/Scav-engeR/vpn_list/main/output/vpn/ipv4.txt', type: 'vpn', enabled: true },
    { name: 'ScavengeR-Datacenter', url: 'https://raw.githubusercontent.com/Scav-engeR/vpn_list/main/output/datacenter/ipv4.txt', type: 'datacenter', enabled: true },
    { name: 'CDN-All', url: 'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/all/all_plain_ipv4.txt', type: 'hosting', enabled: true },
    { name: 'CDN-Only', url: 'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cdn-only/cdn-only_plain_ipv4.txt', type: 'cdn', enabled: true },
    { name: 'IPSet-All', url: 'https://raw.githubusercontent.com/tn3w/IPSet/master/iplist.txt', type: 'vpn', enabled: true },
    { name: 'TOR-Exit-Nodes', url: 'https://check.torproject.org/torbulkexitlist', type: 'tor', enabled: true },
    { name: 'TheSpeedX-Proxy', url: 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt', type: 'proxy', enabled: true },
    { name: 'Datacenter-IPs', url: 'https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt', type: 'datacenter', enabled: true }
  ];

  private constructor() {
    this.logger = Logger.getInstance();
    this.listManager = ListManager.getInstance();
    this.dataDir = path.join(process.cwd(), 'data');
    this.listsDir = path.join(this.dataDir, 'lists');
    this.cacheDir = path.join(this.dataDir, 'cache');
    
    if (!fs.existsSync(this.listsDir)) {
      fs.mkdirSync(this.listsDir, { recursive: true });
    }
    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
    
    this.loadMetadata();
    this.loadSourceCache();
  }

  static getInstance(): ListUpdater {
    if (!ListUpdater.instance) {
      ListUpdater.instance = new ListUpdater();
    }
    return ListUpdater.instance;
  }

  private loadMetadata(): void {
    const metaPath = path.join(this.listsDir, 'update_metadata.json');
    if (fs.existsSync(metaPath)) {
      try {
        this.metadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
      } catch {}
    }
  }

  private saveMetadata(): void {
    const metaPath = path.join(this.listsDir, 'update_metadata.json');
    if (this.metadata) {
      fs.writeFileSync(metaPath, JSON.stringify(this.metadata, null, 2), 'utf-8');
    }
  }

  private loadSourceCache(): void {
    const cachePath = path.join(this.cacheDir, 'source_cache.json');
    if (fs.existsSync(cachePath)) {
      try {
        const cached = JSON.parse(fs.readFileSync(cachePath, 'utf-8'));
        for (const [name, data] of Object.entries(cached)) {
          const entry = data as Partial<SourceCache>;
          if (!entry || !Array.isArray(entry.ips)) continue;

          this.sourceCache.set(name, {
            name: entry.name || name,
            hash: entry.hash || this.calculateHash(entry.ips.join('\n')),
            ips: entry.ips,
            lastUpdated: entry.lastUpdated || new Date(0).toISOString(),
            ipCount: entry.ipCount || entry.ips.length
          });
        }
        this.logger.info(`Loaded cache for ${this.sourceCache.size} sources`);
      } catch (error) {
        this.logger.warn('Failed to load source cache', error);
        this.sourceCache.clear();
      }
    }
  }

  private saveSourceCache(): void {
    const cachePath = path.join(this.cacheDir, 'source_cache.json');
    const data: Record<string, SourceCache> = {};
    for (const [name, cache] of this.sourceCache.entries()) {
      data[name] = cache;
    }
    fs.writeFileSync(cachePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  private calculateHash(content: string): string {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(content).digest('hex');
  }

  async startAutoUpdate(intervalHours: number = 6): Promise<void> {
    if (this.updateInterval) clearInterval(this.updateInterval);
    const intervalMs = intervalHours * 60 * 60 * 1000;

    this.updateInterval = setInterval(() => {
      this.updateAllLists(true).catch((err) => {
        this.logger.error('Scheduled list update failed', err);
      });
    }, intervalMs);
    
    this.logger.info(`Auto-update scheduled every ${intervalHours}h (incremental mode)`);
  }

  stopAutoUpdate(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  async loadListsFromDisk(): Promise<void> {
    if (!fs.existsSync(this.listsDir)) return;
    
    const files = fs.readdirSync(this.listsDir).filter(f => f.endsWith('.txt'));
    if (files.length === 0) {
      this.logger.info('No local list files found');
      return;
    }
    
    let totalIPs = 0;
    let imported = 0;
    
    for (const file of files) {
      if (file === 'update_metadata.json') continue;
      
      try {
        const content = fs.readFileSync(path.join(this.listsDir, file), 'utf-8');
        const sourceName = file.replace(/\.txt$/i, '').replace(/_/g, '-');
        const ips: string[] = [];
        
        for (const line of content.split('\n')) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
          const match = trimmed.match(/(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/);
          if (match) ips.push(match[0]);
        }
        
        totalIPs += ips.length;
        const added = this.listManager.addManyToBlacklist(ips, `Disk:${sourceName}`, 'Disk-Import');
        imported += added;
        
        // Update cache
        const hash = this.calculateHash(content);
        this.sourceCache.set(sourceName, {
          name: sourceName,
          hash: hash,
          ips: ips,
          lastUpdated: new Date().toISOString(),
          ipCount: ips.length
        });
        
        this.logger.info(`  Loaded ${file}: ${ips.length} IPs, +${added} new`);
      } catch (error) {
        this.logger.warn(`Failed to load ${file}`, error);
      }
    }
    
    this.saveSourceCache();
    this.logger.info(`Loaded ${totalIPs} IPs from ${files.length} files, ${imported} imported`);
  }

  async updateAllLists(incremental: boolean = true): Promise<UpdateMetadata> {
    if (this.isUpdating) {
      this.logger.info('Update already in progress, skipping');
      return this.metadata!;
    }
    
    this.isUpdating = true;
    try {
    const startTime = Date.now();
    
    const enabledSources = this.sources.filter(s => s.enabled);
    let totalIPs = 0;
    let imported = 0;
    let skipped = 0;
    let ok = 0;
    let fail = 0;
    let unchanged = 0;

    this.logger.info(`Downloading from ${enabledSources.length} sources (incremental: ${incremental})...`);

    // Download in batches of 3
    for (let i = 0; i < enabledSources.length; i += 3) {
      const batch = enabledSources.slice(i, i + 3);
      const batchResults = await Promise.allSettled(
        batch.map(source => this.downloadListWithCache(source, incremental))
      );
      
      for (let j = 0; j < batchResults.length; j++) {
        const result = batchResults[j];
        const source = batch[j];
        
        if (result.status === 'fulfilled') {
          const { ips, changed, newIps } = result.value;
          
          if (ips.length === 0) {
            fail++;
            this.logger.warn(`  ✗ ${source.name}: Empty response`);
            continue;
          }
          
          if (!changed) {
            unchanged++;
            this.logger.info(`  ✓ ${source.name}: UNCHANGED (${ips.length} IPs, using cache)`);
            continue;
          }
          
          totalIPs += ips.length;
          ok++;
          
          this.saveListToFile(source.name, ips);
          
          // Only add new IPs (incremental update)
          const added = this.listManager.addManyToBlacklist(newIps, `Source:${source.name}`, source.type.toUpperCase());
          imported += added;
          skipped += ips.length - added;
          
          this.logger.info(`  ✓ ${source.name}: ${ips.length} IPs, +${added} new, ${ips.length - added} existing`);
        } else {
          fail++;
          this.logger.warn(`  ✗ ${source.name}: Failed`);
        }
      }
      
      // Delay between batches
      if (i + 3 < enabledSources.length) {
        await this.delay(2000);
      }
    }

    const duration = (Date.now() - startTime) / 1000;
    
    this.metadata = {
      last_update: new Date().toISOString(),
      total_ips: totalIPs,
      imported,
      skipped,
      sources_ok: ok,
      sources_fail: fail,
      duration_seconds: duration,
      incremental
    };
    
    this.saveMetadata();
    this.saveSourceCache();
    
    this.logger.info(`Update complete: ${totalIPs} IPs, +${imported} new, ${skipped} dup, ${ok}/${enabledSources.length} ok, ${unchanged} unchanged, ${fail} fail (${duration}s)`);
    
    return this.metadata;
    } finally {
      this.isUpdating = false;
    }
  }

  private async downloadListWithCache(source: ListSource, incremental: boolean, attempt: number = 1): Promise<{ ips: string[]; changed: boolean; newIps: string[] }> {
    const maxAttempts = 2;
    const timeoutMs = attempt === 1 ? 45000 : 90000;

    try {
      const response = await axios.get(source.url, {
        timeout: timeoutMs,
        responseType: 'text',
        headers: { 
          'User-Agent': 'LythorixAntiVpn/2.0',
          // Add If-None-Match header for ETag caching if available
          ...(source.etag && { 'If-None-Match': source.etag }),
          ...(source.lastModified && { 'If-Modified-Since': source.lastModified })
        },
        validateStatus: (status) => status < 500
      });

      // Check if content not modified (304)
      if (response.status === 304) {
        const cached = this.sourceCache.get(source.name);
        if (cached && Array.isArray(cached.ips)) {
          this.logger.debug(`  ${source.name}: Not modified, using cache`);
          return { ips: cached.ips, changed: false, newIps: [] };
        }
      }

      if (response.status === 404) {
        return { ips: [], changed: false, newIps: [] };
      }

      // Update ETag and Last-Modified for next time
      const etag = response.headers['etag'];
      const lastModified = response.headers['last-modified'];
      if (etag) source.etag = etag;
      if (lastModified) source.lastModified = lastModified;

      const lines = (response.data as string).split('\n');
      const ips: string[] = [];
      const ipRegex = /(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/;

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
        const match = trimmed.match(ipRegex);
        if (match) ips.push(match[0]);
      }

      const uniqueIps = [...new Set(ips)];
      const newHash = this.calculateHash(uniqueIps.join('\n'));
      
      // Check if content actually changed
      const cached = this.sourceCache.get(source.name);
      if (cached && Array.isArray(cached.ips) && cached.hash === newHash && incremental) {
        this.logger.debug(`  ${source.name}: Content unchanged (hash match), using cache`);
        return { ips: cached.ips, changed: false, newIps: [] };
      }

      // Calculate new IPs (ones not in cache)
      let newIps: string[] = [];
      if (cached && Array.isArray(cached.ips) && incremental) {
        const cachedSet = new Set(cached.ips);
        newIps = uniqueIps.filter(ip => !cachedSet.has(ip));
      } else {
        newIps = uniqueIps;
      }

      // Update cache
      this.sourceCache.set(source.name, {
        name: source.name,
        hash: newHash,
        ips: uniqueIps,
        lastUpdated: new Date().toISOString(),
        ipCount: uniqueIps.length
      });

      return { ips: uniqueIps, changed: true, newIps };

    } catch (error: any) {
      if (attempt < maxAttempts) {
        this.logger.warn(`  Retry ${source.name} (${attempt}/${maxAttempts})`);
        await this.delay(2000);
        return this.downloadListWithCache(source, incremental, attempt + 1);
      }
      throw error;
    }
  }

  // Legacy method for backward compatibility
  private async downloadList(source: ListSource, attempt: number = 1): Promise<string[]> {
    const result = await this.downloadListWithCache(source, true, attempt);
    return result.ips;
  }

  private saveListToFile(name: string, ips: string[]): void {
    const filename = name.toLowerCase().replace(/[^a-z0-9]/g, '_') + '.txt';
    const filepath = path.join(this.listsDir, filename);
    fs.writeFileSync(filepath, ips.join('\n'), 'utf-8');
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Force full update (ignore cache)
  async forceFullUpdate(): Promise<UpdateMetadata> {
    this.logger.info('Forcing full update (ignoring cache)...');
    // Clear source cache to force re-download
    this.sourceCache.clear();
    this.saveSourceCache();
    return this.updateAllLists(false);
  }

  getStats(): { total_sources: number; enabled_sources: number; is_updating: boolean; total_ips?: number; lists_dir: string; cached_sources: number } {
    return {
      total_sources: this.sources.length,
      enabled_sources: this.sources.filter(s => s.enabled).length,
      is_updating: this.isUpdating,
      total_ips: this.metadata?.total_ips,
      lists_dir: this.listsDir,
      cached_sources: this.sourceCache.size
    };
  }

  getMetadata(): UpdateMetadata | null {
    return this.metadata;
  }

  getSourceCache(): Map<string, SourceCache> {
    return this.sourceCache;
  }
}
