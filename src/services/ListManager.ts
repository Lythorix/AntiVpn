import * as fs from 'fs';
import * as path from 'path';
import { WhitelistData, BlacklistData, BlacklistEntry, WhitelistEntry } from '../types';
import { Logger } from '../utils/Logger';

export class ListManager {
  private static instance: ListManager;
  private whitelist: any;
  private blacklist: BlacklistData;
  private whitelistPath: string;
  private blacklistPath: string;
  private logger: Logger;

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

  private loadLists(): void {
    try {
      if (fs.existsSync(this.whitelistPath)) {
        this.whitelist = JSON.parse(fs.readFileSync(this.whitelistPath, 'utf-8'));
        if (!this.whitelist.providers) this.whitelist.providers = [];
        if (!this.whitelist.auto_added) this.whitelist.auto_added = [];
      } else this.saveWhitelist();
    } catch (e) { this.whitelist = { ips: [], players: [], providers: [], auto_added: [] }; }

    try {
      if (fs.existsSync(this.blacklistPath)) {
        this.blacklist = JSON.parse(fs.readFileSync(this.blacklistPath, 'utf-8'));
        if (!this.blacklist.auto_added) this.blacklist.auto_added = [];
      } else this.saveBlacklist();
    } catch (e) { this.blacklist = { ips: [], players: [], auto_added: [] }; }
  }

  isWhitelisted(ip: string): boolean {
    if (this.permanentWhitelist.includes(ip)) return true;
    if (this.whitelist.ips.includes(ip)) return true;
    for (const cidr of this.whitelist.ips) {
      if (cidr.includes('/') && this.ipInCIDR(ip, cidr)) return true;
    }
    return false;
  }

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

  addToWhitelist(ip: string, reason: string = 'Auto-added'): void {
    if (this.isWhitelisted(ip)) return;
    this.whitelist.ips.push(ip);
    this.whitelist.auto_added.push({ ip, reason, added_at: new Date().toISOString() });
    this.saveWhitelist();
  }

  isBlacklisted(ip: string): boolean {
    if (this.blacklist.ips.includes(ip)) return true;
    for (const cidr of this.blacklist.ips) {
      if (cidr.includes('/') && this.ipInCIDR(ip, cidr)) return true;
    }
    return false;
  }

  addToBlacklist(ip: string, reason: string = 'VPN/Proxy', method: string = 'Auto'): void {
    if (this.isBlacklisted(ip)) return;
    if (this.isWhitelisted(ip)) {
      this.whitelist.ips = this.whitelist.ips.filter((i: string) => i !== ip);
      this.saveWhitelist();
    }
    this.blacklist.ips.push(ip);
    this.blacklist.auto_added.push({ ip, reason, added_at: new Date().toISOString(), detection_method: method });
    this.saveBlacklist();
    this.logger.warn(`⛔ Blacklisted: ${ip} - ${reason}`);
  }

  getIpStatus(ip: string): 'permanent_whitelist' | 'whitelisted' | 'blacklisted' | 'needs_check' {
    if (this.permanentWhitelist.includes(ip)) return 'permanent_whitelist';
    if (this.isWhitelisted(ip)) return 'whitelisted';
    if (this.isBlacklisted(ip)) return 'blacklisted';
    return 'needs_check';
  }

  private ipInCIDR(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);
    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);
    return (ipNum & mask) === (rangeNum & mask);
  }

  private ipToNumber(ip: string): number {
    if (ip.includes(':')) return 0;
    return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o), 0) >>> 0;
  }

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

  private saveWhitelist(): void {
    try {
      const dir = path.dirname(this.whitelistPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.whitelistPath, JSON.stringify(this.whitelist, null, 2));
    } catch (e) {}
  }

  private saveBlacklist(): void {
    try {
      const dir = path.dirname(this.blacklistPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.blacklistPath, JSON.stringify(this.blacklist, null, 2));
    } catch (e) {}
  }

  getWhitelistStats() { return { ips: this.whitelist.ips.length, auto_added: this.whitelist.auto_added?.length || 0, providers: this.whitelist.providers?.length || 0 }; }
  getBlacklistStats() { return { ips: this.blacklist.ips.length, auto_added: this.blacklist.auto_added?.length || 0 }; }
}