import * as fs from 'fs';
import * as path from 'path';
import { CachedIpData, IpCheckResult } from '../types';
import { Logger } from './Logger';

export class CacheService {
  private static instance: CacheService;
  private cache: Map<string, CachedIpData>;
  private cachePath: string;
  private ttlMs: number;
  private logger: Logger;

  private constructor() {
    this.logger = Logger.getInstance();
    this.cache = new Map();
    this.cachePath = path.join(process.cwd(), 'data', 'checked_ips.json');
    this.ttlMs = 24 * 60 * 60 * 1000; // 24 часа
    this.loadFromDisk();
  }

  static getInstance(): CacheService {
    if (!CacheService.instance) {
      CacheService.instance = new CacheService();
    }
    return CacheService.instance;
  }

  setTTL(hours: number): void {
    this.ttlMs = hours * 60 * 60 * 1000;
  }

  get(ip: string): IpCheckResult | null {
    const cached = this.cache.get(ip);
    
    if (!cached) return null;
    
    // Проверка TTL
    if (Date.now() - cached.timestamp > this.ttlMs) {
      this.cache.delete(ip);
      return null;
    }

    return { ...cached.result, cached: true };
  }

  set(ip: string, result: IpCheckResult): void {
    this.cache.set(ip, {
      result,
      timestamp: Date.now()
    });
    
    // Сохраняем каждые 5 минут
    if (Math.random() < 0.05) {
      this.saveToDisk();
    }
  }

  has(ip: string): boolean {
    const cached = this.cache.get(ip);
    if (!cached) return false;
    return (Date.now() - cached.timestamp) <= this.ttlMs;
  }

  getAll(): Record<string, CachedIpData> {
    const result: Record<string, CachedIpData> = {};
    this.cache.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }

  private loadFromDisk(): void {
    try {
      if (fs.existsSync(this.cachePath)) {
        const raw = fs.readFileSync(this.cachePath, 'utf-8');
        const data = JSON.parse(raw);
        
        for (const [ip, cached] of Object.entries(data)) {
          const entry = cached as CachedIpData;
          if (Date.now() - entry.timestamp <= this.ttlMs) {
            this.cache.set(ip, entry);
          }
        }
        
        this.logger.info(`📦 Cache loaded: ${this.cache.size} entries`);
      }
    } catch (error) {
      this.logger.error('Failed to load cache from disk', error);
    }
  }

  saveToDisk(): void {
    try {
      const data: Record<string, CachedIpData> = {};
      this.cache.forEach((value, key) => {
        data[key] = value;
      });
      
      fs.writeFileSync(this.cachePath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Failed to save cache to disk', error);
    }
  }

  clear(): void {
    this.cache.clear();
    this.saveToDisk();
  }
}