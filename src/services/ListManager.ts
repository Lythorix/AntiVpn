// src/services/ListManager.ts - UPDATED with blacklist.json loading
import * as fs from 'fs';
import * as path from 'path';
import { WhitelistData, BlacklistData, BlacklistEntry, WhitelistEntry } from '../types';
import { Logger } from '../utils/Logger';

// List manager - handles whitelist and blacklist operations - singleton pattern
export class ListManager {
  private static instance: ListManager;
  private whitelist: WhitelistData;
  private blacklist: BlacklistData;
  private whitelistPath: string;
  private blacklistPath: string;
  private logger: Logger;
  private blacklistSet: Set<string> = new Set();
  private blacklistCidrs: string[] = [];

  // Permanent whitelist - always trusted
  private permanentWhitelist: string[] = ['127.0.0.1', 'localhost', '::1'];

  private constructor() {
    this.logger = Logger.getInstance();
    this.whitelistPath = path.join(process.cwd(), 'data', 'whitelist.json');
    this.blacklistPath = path.join(process.cwd(), 'data', 'blacklist.json');
    this.whitelist = { ips: [], players: [], providers: [], auto_added: [] };
    this.blacklist = { ips: [], players: [], auto_added: [] };
    this.loadLists();
  }

  static getInstance(): ListManager {
    if (!ListManager.instance) ListManager.instance = new ListManager();
    return ListManager.instance;
  }

  // Load lists from disk
  private loadLists(): void {
    try {
      if (fs.existsSync(this.whitelistPath)) {
        this.whitelist = JSON.parse(fs.readFileSync(this.whitelistPath, 'utf-8'));
        if (!this.whitelist.providers) this.whitelist.providers = [];
        if (!this.whitelist.auto_added) this.whitelist.auto_added = [];
        this.logger.info(`Loaded whitelist: ${this.whitelist.ips.length} IPs`);
      } else this.saveWhitelist();
    } catch (e) { 
      this.whitelist = { ips: [], players: [], providers: [], auto_added: [] };
      this.logger.warn('Failed to load whitelist, using empty');
    }

    try {
      if (fs.existsSync(this.blacklistPath)) {
        this.blacklist = JSON.parse(fs.readFileSync(this.blacklistPath, 'utf-8'));
        if (!this.blacklist.auto_added) this.blacklist.auto_added = [];
        this.logger.info(`Loaded blacklist: ${this.blacklist.ips.length} IPs`);
      } else this.saveBlacklist();
    } catch (e) { 
      this.blacklist = { ips: [], players: [], auto_added: [] };
      this.logger.warn('Failed to load blacklist, using empty');
    }

    this.rebuildBlacklistIndex();
  }

  private rebuildBlacklistIndex(): void {
    this.blacklistSet.clear();
    this.blacklistCidrs = [];
    for (const ip of this.blacklist.ips) {
      if (ip.includes('/')) this.blacklistCidrs.push(ip);
      else this.blacklistSet.add(ip);
    }
    this.logger.debug(`Blacklist index rebuilt: ${this.blacklistSet.size} IPs, ${this.blacklistCidrs.length} CIDRs`);
  }

  // Check if IP is whitelisted
  isWhitelisted(ip: string): boolean {
    if (this.permanentWhitelist.includes(ip)) return true;
    if (this.whitelist.ips.includes(ip)) return true;
    // Check CIDR ranges
    for (const cidr of this.whitelist.ips) {
      if (cidr.includes('/') && this.ipInCIDR(ip, cidr)) return true;
    }
    return false;
  }

  // Check if provider is whitelisted by name
  isWhitelistedByProvider(isp: string, org: string): boolean {
    const ispLower = (isp || '').toLowerCase().trim();
    const orgLower = (org || '').toLowerCase().trim();
    const providers = this.whitelist.providers || [];
    
    for (const provider of providers) {
      const pLower = provider.toLowerCase();
      if (ispLower.includes(pLower) || orgLower.includes(pLower)) {
        return true;
      }
    }
    return false;
  }

  // Add IP to whitelist
  addToWhitelist(ip: string, reason: string = 'Auto-added'): void {
    if (this.isWhitelisted(ip)) return;
    this.whitelist.ips.push(ip);
    this.whitelist.auto_added.push({ ip, reason, added_at: new Date().toISOString() });
    this.saveWhitelist();
  }

  // Check if IP is blacklisted
  isBlacklisted(ip: string): boolean {
    if (this.blacklistSet.has(ip)) return true;
    for (const cidr of this.blacklistCidrs) {
      if (this.ipInCIDR(ip, cidr)) return true;
    }
    return false;
  }

  // Add IP to blacklist
  addToBlacklist(ip: string, reason: string = 'VPN/Proxy', method: string = 'Auto'): void {
    if (this.isBlacklisted(ip)) return;
    // Remove from whitelist if present
    if (this.isWhitelisted(ip)) {
      this.whitelist.ips = this.whitelist.ips.filter((i: string) => i !== ip);
      this.saveWhitelist();
    }
    if (ip.includes('/')) this.blacklistCidrs.push(ip);
    else this.blacklistSet.add(ip);
    this.blacklist.ips.push(ip);
    this.blacklist.auto_added.push({ ip, reason, added_at: new Date().toISOString(), detection_method: method });
    this.saveBlacklist();
    this.logger.warn(`Blacklisted: ${ip} - ${reason}`);
  }

  // Batch-add IPs to blacklist (single disk write)
  addManyToBlacklist(ips: string[], reason: string, method: string = 'Auto-Import'): number {
    let added = 0;

    for (const ip of ips) {
      if (this.isWhitelisted(ip) || this.isPrivateIP(ip)) continue;
      if (ip.includes('/')) {
        if (this.blacklistCidrs.includes(ip)) continue;
        this.blacklistCidrs.push(ip);
      } else {
        if (this.blacklistSet.has(ip)) continue;
        this.blacklistSet.add(ip);
      }
      this.blacklist.ips.push(ip);
      added++;
    }

    if (added > 0) {
      this.blacklist.auto_added.push({
        ip: `batch:${added}`,
        reason,
        added_at: new Date().toISOString(),
        detection_method: method
      });
      this.saveBlacklist();
      this.logger.info(`Imported ${added} IPs (${reason})`);
    }

    return added;
  }

  // Get IP status
  getIpStatus(ip: string): 'permanent_whitelist' | 'whitelisted' | 'blacklisted' | 'needs_check' {
    if (this.permanentWhitelist.includes(ip)) return 'permanent_whitelist';
    if (this.isWhitelisted(ip)) return 'whitelisted';
    if (this.isBlacklisted(ip)) return 'blacklisted';
    return 'needs_check';
  }

  // Check if IP is in CIDR range
  private ipInCIDR(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);
    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);
    return (ipNum & mask) === (rangeNum & mask);
  }

  // Convert IP to number for CIDR calculations
  private ipToNumber(ip: string): number {
    if (ip.includes(':')) return 0; // Skip IPv6
    return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o), 0) >>> 0;
  }

  // Check if IP is private/local
  isPrivateIP(ip: string): boolean {
    if (ip === '::1' || ip === 'localhost') return true;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    return false;
  }

  // Save whitelist to disk
  private saveWhitelist(): void {
    try {
      const dir = path.dirname(this.whitelistPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.whitelistPath, JSON.stringify(this.whitelist, null, 2));
      this.logger.debug(`Whitelist saved: ${this.whitelist.ips.length} IPs`);
    } catch (e) {
      this.logger.error('Failed to save whitelist', e);
    }
  }

  // Save blacklist to disk
  private saveBlacklist(): void {
    try {
      const dir = path.dirname(this.blacklistPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.blacklistPath, JSON.stringify(this.blacklist, null, 2));
      this.logger.debug(`Blacklist saved: ${this.blacklist.ips.length} IPs`);
    } catch (e) {
      this.logger.error('Failed to save blacklist', e);
    }
  }

  // Get whitelist statistics
  getWhitelistStats() { 
    return { 
      ips: this.whitelist.ips.length, 
      auto_added: this.whitelist.auto_added?.length || 0, 
      providers: this.whitelist.providers?.length || 0 
    }; 
  }

  // Get blacklist statistics
  getBlacklistStats() { 
    return { 
      ips: this.blacklist.ips.length, 
      auto_added: this.blacklist.auto_added?.length || 0 
    }; 
  }

  // Get all blacklisted IPs
  getAllBlacklistedIps(): string[] {
    return [...this.blacklist.ips];
  }

  // Get all blacklisted entries with details
  getBlacklistEntries(): BlacklistEntry[] {
    return [...this.blacklist.auto_added];
  }

  // Load custom blacklist from a file (for manual imports)
  async loadCustomBlacklist(filePath: string): Promise<number> {
    try {
      if (!fs.existsSync(filePath)) {
        this.logger.warn(`Blacklist file not found: ${filePath}`);
        return 0;
      }

      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      const ips: string[] = [];
      
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
        
        // Check if line contains IP (with optional comment after space)
        const ipMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)/);
        if (ipMatch) {
          ips.push(ipMatch[1]);
        }
      }

      if (ips.length > 0) {
        const added = this.addManyToBlacklist(ips, `Custom import from ${filePath}`, 'CustomFile');
        this.logger.info(`Loaded ${added} IPs from custom blacklist: ${filePath}`);
        return added;
      }
      
      return 0;
    } catch (error) {
      this.logger.error(`Failed to load custom blacklist: ${filePath}`, error);
      return 0;
    }
  }

  // Parse blacklist from text format (one IP per line, supports comments)
  parseBlacklistText(text: string): string[] {
    const lines = text.split('\n');
    const ips: string[] = [];
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
      
      const ipMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)/);
      if (ipMatch) {
        ips.push(ipMatch[1]);
      }
    }
    
    return ips;
  }
}