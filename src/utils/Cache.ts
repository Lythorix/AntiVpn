import * as fs from 'fs';
import * as path from 'path';
import { CachedIpData, IpCheckResult } from '../types';
import { Logger } from './Logger';

// Cache service for IP check results - singleton pattern
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
    this.ttlMs = 24 * 60 * 60 * 1000; // 24 hours default TTL
    this.loadFromDisk();
  }

  static getInstance(): CacheService {
    if (!CacheService.instance) {
      CacheService.instance = new CacheService();
    }
    return CacheService.instance;
  }

  // Set cache TTL in hours
  setTTL(hours: number): void {
    this.ttlMs = hours * 60 * 60 * 1000;
  }

  // Get cached IP check result
  get(ip: string): IpCheckResult | null {
    const cached = this.cache.get(ip);
    
    if (!cached) return null;
    
    // Check TTL expiration
    if (Date.now() - cached.timestamp > this.ttlMs) {
      this.cache.delete(ip);
      return null;
    }

    return { ...cached.result, cached: true };
  }

  // Set IP check result in cache
  set(ip: string, result: IpCheckResult): void {
    this.cache.set(ip, {
      result,
      timestamp: Date.now()
    });
    
    // Save to disk periodically (5% chance)
    if (Math.random() < 0.05) {
      this.saveToDisk();
    }
  }

  // Check if IP exists in cache and is valid
  has(ip: string): boolean {
    const cached = this.cache.get(ip);
    if (!cached) return false;
    return (Date.now() - cached.timestamp) <= this.ttlMs;
  }

  // Get all cached entries
  getAll(): Record<string, CachedIpData> {
    const result: Record<string, CachedIpData> = {};
    this.cache.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }

  // Load cache from disk
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
        
        this.logger.info(`Cache loaded: ${this.cache.size} entries`);
      }
    } catch (error) {
      this.logger.error('Failed to load cache from disk', error);
    }
  }

  // Save cache to disk
  saveToDisk(): void {
    try {
      const dir = path.dirname(this.cachePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      const data: Record<string, CachedIpData> = {};
      this.cache.forEach((value, key) => {
        data[key] = value;
      });
      
      fs.writeFileSync(this.cachePath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Failed to save cache to disk', error);
    }
  }

  // Clear all cached data
  clear(): void {
    this.cache.clear();
    this.saveToDisk();
  }
}