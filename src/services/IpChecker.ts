// src/services/IpChecker.ts - FIXED: ALL NULL RESULTS PROTECTED
import axios, { AxiosInstance } from 'axios';
import { IpCheckResult, AppConfig } from '../types';
import { CacheService } from '../utils/Cache';
import { Logger } from '../utils/Logger';
import { ListManager } from './ListManager';
import { MlDetector } from './MlDetector';
import { 
  INSTANT_BAN_KEYWORDS,
  VPN_KEYWORDS,
  DATACENTER_KEYWORDS,
  PROXY_KEYWORDS,
  HOSTING_KEYWORDS,
  TRUSTED_PROVIDERS,
} from './ProviderLists';
import * as dns from 'dns';
import { promisify } from 'util';
import * as net from 'net';
import * as http from 'http';
import * as tls from 'tls';
import { execSync } from 'child_process';

const dnsReverse = promisify(dns.reverse);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);

export class IpChecker {
  private static instance: IpChecker | null = null;
  private httpClient: AxiosInstance;
  private cache: CacheService;
  private listManager: ListManager;
  private logger: Logger;
  private mlDetector: MlDetector;
  private config: AppConfig | null = null;
  private isInitialized: boolean = false;

  private suspiciousRanges = [
    { range: '185.220.100.0', mask: 24, reason: 'TOR Exit Node' },
    { range: '185.220.101.0', mask: 24, reason: 'TOR Exit Node' },
    { range: '185.220.102.0', mask: 24, reason: 'TOR Exit Node' },
    { range: '146.70.0.0', mask: 16, reason: 'M247 VPN/Hosting' },
    { range: '194.156.0.0', mask: 16, reason: 'M247 Network' },
    { range: '5.255.0.0', mask: 16, reason: 'VPN/Proxy Range' },
    { range: '45.136.0.0', mask: 16, reason: 'Hosting' },
    { range: '45.137.0.0', mask: 16, reason: 'VPN/Proxy' },
    { range: '45.138.0.0', mask: 16, reason: 'Datacenter' },
    { range: '45.139.0.0', mask: 16, reason: 'Hosting' },
    { range: '45.140.0.0', mask: 16, reason: 'VPN' },
    { range: '45.141.0.0', mask: 16, reason: 'Proxy' },
    { range: '45.142.0.0', mask: 16, reason: 'VPN Network' },
    { range: '45.143.0.0', mask: 16, reason: 'Hosting' },
    { range: '45.144.0.0', mask: 16, reason: 'Datacenter' },
    { range: '45.145.0.0', mask: 16, reason: 'VPN' },
    { range: '45.146.0.0', mask: 16, reason: 'Proxy' },
    { range: '185.65.0.0', mask: 16, reason: 'VPN Network' },
    { range: '185.107.0.0', mask: 16, reason: 'TOR/Hosting' },
    { range: '185.129.0.0', mask: 16, reason: 'Proxy Range' },
    { range: '185.165.0.0', mask: 16, reason: 'VPN Provider' },
    { range: '185.183.0.0', mask: 16, reason: 'Datacenter' },
    { range: '185.211.0.0', mask: 16, reason: 'Hosting' },
    { range: '185.230.0.0', mask: 16, reason: 'VPN Service' },
    { range: '185.243.0.0', mask: 16, reason: 'Proxy Network' },
    { range: '192.95.0.0', mask: 16, reason: 'TOR Exit' },
    { range: '198.98.0.0', mask: 16, reason: 'TOR Network' },
    { range: '204.152.0.0', mask: 16, reason: 'Datacenter' },
    { range: '205.185.0.0', mask: 16, reason: 'VPN Provider' },
    { range: '209.141.0.0', mask: 16, reason: 'Hosting' },
    { range: '212.102.0.0', mask: 16, reason: 'VPN/Proxy' },
    { range: '216.218.0.0', mask: 16, reason: 'TOR Exit' },
    { range: '217.138.0.0', mask: 16, reason: 'Datacenter' },
  ];

  private constructor() {
    this.logger = Logger.getInstance();
    this.cache = CacheService.getInstance();
    this.listManager = ListManager.getInstance();
    this.mlDetector = MlDetector.getInstance();
    this.httpClient = axios.create({
      timeout: 2000,
      headers: { 'User-Agent': 'LythorixAntiVpn/3.0', 'Accept': 'application/json' }
    });
  }

  static getInstance(config?: AppConfig): IpChecker {
    if (!IpChecker.instance) {
      IpChecker.instance = new IpChecker();
    }
    if (config && !IpChecker.instance.isInitialized) {
      IpChecker.instance.initialize(config);
    }
    return IpChecker.instance;
  }

  private initialize(config: AppConfig): void {
    this.config = config;
    this.isInitialized = true;
    this.logger.info('IpChecker initialized - 36 methods parallel - max 2s');
  }

  private ensureInitialized(): void {
    if (!this.isInitialized || !this.config) {
      throw new Error('IpChecker not initialized');
    }
  }

  async checkIp(ip: string): Promise<IpCheckResult> {
    this.ensureInitialized();

    if (this.listManager.isWhitelisted(ip)) {
      return this.createCleanResult(ip, 'Whitelisted', '', '', '');
    }
    if (this.listManager.isPrivateIP(ip)) {
      return this.createCleanResult(ip, 'Local', '', '', '');
    }
    if (this.listManager.isBlacklisted(ip)) {
      return this.createBanResult(ip, { country: 'Blacklisted', city: '', isp: 'Blacklisted', org: 'Blacklisted' }, 100);
    }
    const cached = this.cache.get(ip);
    if (cached) return cached;
    const rangeCheck = this.checkSuspiciousRanges(ip);
    if (rangeCheck) {
      const result = this.createBanResult(ip, { country: 'Suspicious Range', city: '', isp: rangeCheck, org: rangeCheck }, 95);
      this.cache.set(ip, result);
      this.listManager.addToBlacklist(ip, `Range: ${rangeCheck}`, 'RangeDB');
      return result;
    }

    const startTime = Date.now();
    
    const results = await Promise.allSettled([
      this.withTimeout(this.checkIpApi(ip), 1500),
      this.withTimeout(this.checkIpwhois(ip), 1500),
      this.withTimeout(this.checkIpapiCo(ip), 1500),
      this.withTimeout(this.checkFreeipapi(ip), 1500),
      this.withTimeout(this.checkIpinfo(ip), 1500),
      this.withTimeout(this.checkIpGeolocation(ip), 1500),
      this.withTimeout(this.checkAbstractApi(ip), 1500),
      this.withTimeout(this.checkIpStack(ip), 1500),
      this.withTimeout(this.checkVpnApiService(ip), 1500),
      this.withTimeout(this.checkShodanDns(ip), 1500),
      this.withTimeout(this.checkReverseDNS(ip), 1000),
      this.withTimeout(this.checkPTRRecord(ip), 1000),
      this.withTimeout(this.checkMXRecord(ip), 1000),
      this.withTimeout(this.checkTXTRecord(ip), 1000),
      this.withTimeout(this.checkNSRecord(ip), 1000),
      this.withTimeout(this.checkOpenPorts(ip), 1500),
      this.withTimeout(this.checkTTL(ip), 1000),
      this.withTimeout(this.checkHttpHeaders(ip), 1000),
      this.withTimeout(this.checkLatency(ip), 1000),
      this.withTimeout(this.checkJA3(ip), 1000),
      this.withTimeout(this.checkAbuseIPDB(ip), 1500),
      this.withTimeout(this.checkBGP(ip), 1500),
      this.withTimeout(this.checkWhois(ip), 1500),
      this.withTimeout(this.checkWebRTC(ip), 1500),
      this.withTimeout(this.checkDNSLeak(ip), 1500),
      this.withTimeout(this.checkProxyCheck(ip), 1500),
      this.withTimeout(this.checkIPQuality(ip), 1500),
      this.withTimeout(this.checkVpnApi(ip), 1500),
      this.withTimeout(this.checkIPIntel(ip), 1500),
      this.withTimeout(this.checkIPRegistry(ip), 1500),
      this.withTimeout(this.checkGRETunnel(ip), 800),
      this.withTimeout(this.checkSYNFlood(ip), 800),
      this.withTimeout(this.checkICMPResponse(ip), 800),
      this.withTimeout(this.checkHTTPFingerprint(ip), 1000),
      this.withTimeout(this.checkTLSFingerprint(ip), 1000),
      this.withTimeout(this.checkSNICheck(ip), 1000),
    ]);

    const duration = Date.now() - startTime;
    this.logger.debug(`36 methods completed in ${duration}ms`);

    const g = (index: number, defaultValue: any = {}) => {
      const result = results[index];
      if (result && result.status === 'fulfilled' && result.value !== null && result.value !== undefined) {
        return result.value;
      }
      return defaultValue;
    };

    const apiResults = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map(i => g(i, null));
    
    let country = 'Unknown', city = 'Unknown', isp = 'Unknown', org = 'Unknown';
    let apiVpnVotes = 0, apiProxyVotes = 0, apiTorVotes = 0, apiHostingVotes = 0, apiDatacenterVotes = 0;

    for (const d of apiResults) {
      if (d) {
        if (d.country && d.country !== 'Unknown') country = d.country;
        if (d.city && d.city !== 'Unknown') city = d.city;
        if (d.isp && d.isp !== 'Unknown') isp = d.isp;
        if (d.org && d.org !== 'Unknown') org = d.org;
        if (d.isVpn) apiVpnVotes++;
        if (d.isProxy) apiProxyVotes++;
        if (d.isTor) apiTorVotes++;
        if (d.isHosting) apiHostingVotes++;
        if (d.isDatacenter) apiDatacenterVotes++;
      }
    }

    const rDnsResult = g(10, { isVpn: false, isHosting: false, hostname: '' });
    const ptrResult = g(11, { isVpn: false, isHosting: false, hostname: '' });
    const mxResult = g(12, { isSuspicious: false, exchanges: [] });
    const txtResult = g(13, { isSuspicious: false, records: [] });
    const nsResult = g(14, { isSuspicious: false, servers: [] });

    const portsResult = g(15, { isProxy: false, openPorts: [] });
    const ttlResult = g(16, { isSuspicious: false, ttl: 0 });
    const headersResult = g(17, { isProxy: false, headers: [] });
    const latencyResult = g(18, { latency: -1, isSuspicious: false });
    const ja3Result = g(19, { isVpn: false, fingerprint: '' });
    const abuseResult = g(20, { isTor: false, isHosting: false, score: 0 });
    const bgpResult = g(21, { isHosting: false, asn: '' });
    const whoisResult = g(22, { isHosting: false, org: '' });
    const webrtcResult = g(23, { isVpn: false, isProxy: false });
    const dnsLeakResult = g(24, { isVpn: false, isProxy: false });
    const proxyCheckResult = g(25, { isVpn: false, isProxy: false, isTor: false, isHosting: false });
    const ipQualityResult = g(26, { isVpn: false, isProxy: false, isTor: false, isHosting: false });
    const vpnApiResult = g(27, { isVpn: false, isProxy: false });
    const ipIntelResult = g(28, { isVpn: false, isProxy: false });
    const ipRegistryResult = g(29, { isVpn: false, isProxy: false });
    const greResult = g(30, false);
    const synResult = g(31, { isProxy: false });
    const icmpResult = g(32, { isSuspicious: false, response: '' });
    const httpFpResult = g(33, { isProxy: false, server: '' });
    const tlsFpResult = g(34, { isVpn: false, cipher: '' });
    const sniResult = g(35, { isVpn: false, sni: '' });

    const ispLower = isp.toLowerCase().trim();
    const orgLower = org.toLowerCase().trim();
    const combined = `${ispLower} ${orgLower}`;
    const normalized = this.normalizeProviderText(combined);

    if (this.hasInstantBanKeyword(normalized)) {
      const result = this.createBanResult(ip, { country, city, isp, org }, 100);
      this.cache.set(ip, result);
      this.listManager.addToBlacklist(ip, 'InstantBan keyword', 'Keyword');
      this.logger.warn(`BLOCKED: ${ip} - ${isp} (Keyword)`);
      return result;
    }
    if (this.matchesKeywords(normalized, VPN_KEYWORDS)) {
      const result = this.createVpnResult(ip, { country, city, isp, org });
      this.cache.set(ip, result);
      this.listManager.addToBlacklist(ip, 'VPN keyword', 'Keyword');
      this.logger.warn(`BLOCKED: ${ip} - ${isp} (VPN)`);
      return result;
    }
    if (this.matchesKeywords(normalized, PROXY_KEYWORDS)) {
      const result = this.createProxyResult(ip, { country, city, isp, org });
      this.cache.set(ip, result);
      this.listManager.addToBlacklist(ip, 'Proxy keyword', 'Keyword');
      this.logger.warn(`BLOCKED: ${ip} - ${isp} (Proxy)`);
      return result;
    }
    if (this.matchesKeywords(normalized, HOSTING_KEYWORDS)) {
      const result = this.createHostingResult(ip, { country, city, isp, org });
      this.cache.set(ip, result);
      this.listManager.addToBlacklist(ip, 'Hosting keyword', 'Keyword');
      this.logger.warn(`BLOCKED: ${ip} - ${isp} (Hosting)`);
      return result;
    }
    if (this.matchesKeywords(normalized, DATACENTER_KEYWORDS)) {
      const result = this.createDatacenterResult(ip, { country, city, isp, org });
      this.cache.set(ip, result);
      this.listManager.addToBlacklist(ip, 'Datacenter keyword', 'Keyword');
      this.logger.warn(`BLOCKED: ${ip} - ${isp} (Datacenter)`);
      return result;
    }
    if (this.isTrustedProvider(combined)) {
      const result = this.createCleanResult(ip, country, city, isp, org);
      this.cache.set(ip, result);
      this.logger.info(`ALLOWED: ${ip} - ${isp} (Trusted)`);
      return result;
    }

    const isVpn = apiVpnVotes >= 1 || rDnsResult.isVpn || ttlResult.isSuspicious || ja3Result.isVpn || 
                  webrtcResult.isVpn || dnsLeakResult.isVpn || proxyCheckResult.isVpn || ipQualityResult.isVpn ||
                  vpnApiResult.isVpn || ipIntelResult.isVpn || ipRegistryResult.isVpn || ptrResult.isVpn ||
                  mxResult.isSuspicious || tlsFpResult.isVpn || sniResult.isVpn;

    const isProxy = apiProxyVotes >= 1 || portsResult.isProxy || headersResult.isProxy || webrtcResult.isProxy || 
                    dnsLeakResult.isProxy || proxyCheckResult.isProxy || ipQualityResult.isProxy || vpnApiResult.isProxy ||
                    ipIntelResult.isProxy || ipRegistryResult.isProxy || greResult || synResult.isProxy || httpFpResult.isProxy;

    const isTor = apiTorVotes >= 1 || abuseResult.isTor || proxyCheckResult.isTor || ipQualityResult.isTor || txtResult.isSuspicious;

    const isHosting = apiHostingVotes >= 1 || rDnsResult.isHosting || bgpResult.isHosting || whoisResult.isHosting || 
                      abuseResult.isHosting || proxyCheckResult.isHosting || ipQualityResult.isHosting || ptrResult.isHosting || 
                      nsResult.isSuspicious;

    const isDatacenter = apiDatacenterVotes >= 1 || isHosting || icmpResult.isSuspicious;

    try {
      const mlFeatures = this.mlDetector.extractFeatures({
        ip, latency: latencyResult.latency, ttl: ttlResult.ttl, openPorts: portsResult.openPorts,
        hasProxyHeaders: headersResult.isProxy, hasPtrRecord: rDnsResult.hostname !== '',
        hasMxRecord: mxResult.exchanges.length > 0, reverseDns: rDnsResult.hostname, isp, org,
        asn: bgpResult.asn, prefixCount: 0, tlsVersion: tlsFpResult.cipher, cipherStrength: 0,
        certValidityDays: 0, abuseScore: abuseResult.score, isTorExit: abuseResult.isTor,
        knownVpnRange: false, isDatacenterRange: bgpResult.isHosting, ipChanges24h: 0,
        countryChanges24h: 0, avgSessionDuration: 0,
      });

      const mlPrediction = this.mlDetector.predict(mlFeatures);

      if (mlPrediction && mlPrediction.confidence > 0.8 && mlPrediction.score > 70) {
        const mlResult: IpCheckResult = {
          ip, is_vpn: mlPrediction.isVpn, is_proxy: mlPrediction.isProxy, is_tor: mlPrediction.isTor,
          is_hosting: mlPrediction.isHosting, is_datacenter: mlPrediction.isDatacenter, country, city, isp,
          organization: org, risk_score: mlPrediction.score, threat_level: mlPrediction.threatLevel,
          checked_at: new Date().toISOString(), cached: false
        };
        const isSuspicious = mlPrediction.isVpn || mlPrediction.isProxy || mlPrediction.isTor || mlPrediction.isHosting || mlPrediction.isDatacenter;
        this.mlDetector.addTrainingSample(mlFeatures, isSuspicious ? 1 : 0, mlPrediction.confidence);
        this.cache.set(ip, mlResult);
        if (isSuspicious) {
          this.listManager.addToBlacklist(ip, `ML (${mlPrediction.score}%)`, 'ML');
          this.logger.warn(`BLOCKED: ${ip} - ${isp} (ML ${mlPrediction.score}%)`);
        }
        return mlResult;
      }
    } catch (mlError) {
      this.logger.debug('ML detection skipped', mlError);
    }

    let riskScore = 0;
    if (isTor) riskScore = 100;
    else if (isVpn && isProxy) riskScore = 95;
    else if (isVpn) riskScore = 85;
    else if (isProxy) riskScore = 75;
    else if (isHosting || isDatacenter) riskScore = 60;

    const threatLevel = isTor ? 'critical' : isVpn ? 'high' : isProxy ? 'medium' : isHosting || isDatacenter ? 'low' : 'low';

    const finalResult: IpCheckResult = {
      ip, is_vpn: isVpn, is_proxy: isProxy, is_tor: isTor, is_hosting: isHosting, is_datacenter: isDatacenter,
      country, city, isp, organization: org, risk_score: riskScore, threat_level: threatLevel,
      checked_at: new Date().toISOString(), cached: false
    };

    this.cache.set(ip, finalResult);

    if (isVpn || isProxy || isTor || isHosting || isDatacenter) {
      this.listManager.addToBlacklist(ip, 'Multi-method', 'Heavy');
      this.logger.warn(`BLOCKED: ${ip} - ${isp} [V:${isVpn} P:${isProxy} T:${isTor} H:${isHosting} D:${isDatacenter}]`);
    } else {
      this.logger.info(`ALLOWED: ${ip} - ${isp} (${country})`);
    }

    return finalResult;
  }

  private async withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
    return Promise.race([promise, new Promise<null>(r => setTimeout(() => r(null), ms))]);
  }

  // ===== 10 API SERVICES =====
  private async checkIpApi(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`http://ip-api.com/json/${ip}?fields=country,countryCode,city,isp,org,proxy,hosting,query`);
      const d = r.data;
      return d?.isp ? { country: d.country, city: d.city, isp: d.isp, org: d.org || d.isp, isProxy: d.proxy || false, isHosting: d.hosting || false } : null;
    } catch { return null; }
  }
  private async checkIpwhois(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://ipwhois.app/json/${ip}`);
      const d = r.data;
      return d?.isp ? { country: d.country, city: d.city, isp: d.isp, org: d.org || d.isp, isVpn: d.type === 'VPN', isProxy: d.type === 'Proxy', isHosting: d.type === 'Hosting' } : null;
    } catch { return null; }
  }
  private async checkIpapiCo(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://ipapi.co/${ip}/json/`);
      const d = r.data;
      return d?.org ? { country: d.country_name, city: d.city, isp: d.org, org: d.org, isHosting: d.asn?.type === 'hosting' } : null;
    } catch { return null; }
  }
  private async checkFreeipapi(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://freeipapi.com/api/json/${ip}`);
      const d = r.data;
      return d?.isp ? { country: d.countryName, city: d.cityName, isp: d.isp, org: d.isp, isVpn: d.isVpn || false, isProxy: d.isProxy || false, isTor: d.isTor || false } : null;
    } catch { return null; }
  }
  private async checkIpinfo(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://ipinfo.io/${ip}/json`);
      const d = r.data;
      return d?.org ? { country: d.country, city: d.city, isp: d.org, org: d.org, isVpn: d.privacy?.vpn || false, isProxy: d.privacy?.proxy || false, isTor: d.privacy?.tor || false, isHosting: d.privacy?.hosting || false } : null;
    } catch { return null; }
  }
  private async checkIpGeolocation(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://api.ipgeolocation.io/ipgeo?apiKey=${process.env.IPGEO_KEY || ''}&ip=${ip}`);
      const d = r.data;
      return d?.isp ? { country: d.country_name, city: d.city, isp: d.isp, org: d.organization || d.isp, isVpn: d.is_vpn || false, isProxy: d.is_proxy || false, isTor: d.is_tor || false, isHosting: d.is_hosting || false, isDatacenter: d.is_data_center || false } : null;
    } catch { return null; }
  }
  private async checkAbstractApi(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://ipgeolocation.abstractapi.com/v1/?api_key=${process.env.ABSTRACT_KEY || ''}&ip_address=${ip}`);
      const d = r.data;
      return d?.isp ? { country: d.country, city: d.city, isp: d.isp, org: d.organization || d.isp, isVpn: d.security?.is_vpn || false, isHosting: d.security?.is_data_center || false } : null;
    } catch { return null; }
  }
  private async checkIpStack(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`http://api.ipstack.com/${ip}?access_key=${process.env.IPSTACK_KEY || ''}`);
      const d = r.data;
      return d?.ip ? { country: d.country_name, city: d.city, isp: d.isp || '', org: d.organization || d.isp || '', isProxy: d.proxy || false, isHosting: d.type === 'hosting' } : null;
    } catch { return null; }
  }
  private async checkVpnApiService(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://vpnapi.io/api/${ip}?key=${process.env.VPNAPI_KEY || ''}`);
      const d = r.data?.security;
      return { country: r.data?.location?.country, city: r.data?.location?.city, isp: r.data?.network?.isp || '', org: r.data?.network?.organization || '', isVpn: d?.vpn || false, isProxy: d?.proxy || false, isTor: d?.tor || false, isHosting: d?.relay || false };
    } catch { return null; }
  }
  private async checkShodanDns(ip: string): Promise<any> {
    try {
      const r = await this.httpClient.get(`https://api.shodan.io/dns/reverse?ips=${ip}&key=${process.env.SHODAN_KEY || ''}`);
      const d = r.data;
      const hostnames = d?.[ip] || [];
      const hostname = hostnames[0] || '';
      const lower = hostname.toLowerCase();
      return { country: 'Unknown', city: 'Unknown', isp: hostname, org: hostname, isVpn: ['vpn', 'proxy', 'tor'].some(k => lower.includes(k)), isHosting: ['host', 'server', 'cloud', 'vps'].some(k => lower.includes(k)) };
    } catch { return null; }
  }

  // ===== 5 DNS METHODS =====
  private async checkReverseDNS(ip: string): Promise<{ isVpn: boolean; isHosting: boolean; hostname: string }> {
    try {
      const hostnames = await dnsReverse(ip);
      const hostname = hostnames[0] || '';
      const lower = hostname.toLowerCase();
      return { isVpn: ['vpn', 'proxy', 'tor', 'tunnel', 'relay', 'anon', 'hide'].some(k => lower.includes(k)), isHosting: ['vps', 'host', 'server', 'cloud', 'datacenter', 'colo'].some(k => lower.includes(k)), hostname };
    } catch { return { isVpn: false, isHosting: false, hostname: '' }; }
  }
  private async checkPTRRecord(ip: string): Promise<{ isVpn: boolean; isHosting: boolean; hostname: string }> {
    try {
      const reversed = ip.split('.').reverse().join('.');
      const hostnames = await dnsResolve4(`${reversed}.in-addr.arpa`).catch(() => []);
      const hostname = hostnames[0] || '';
      const lower = hostname.toLowerCase();
      return { isVpn: ['vpn', 'proxy', 'tor'].some(k => lower.includes(k)), isHosting: ['host', 'server', 'cloud'].some(k => lower.includes(k)), hostname };
    } catch { return { isVpn: false, isHosting: false, hostname: '' }; }
  }
  private async checkMXRecord(ip: string): Promise<{ isSuspicious: boolean; exchanges: string[] }> {
    try {
      const reversed = ip.split('.').reverse().join('.');
      const exchanges = await dnsResolveMx(`${reversed}.in-addr.arpa`).catch(() => []);
      const names = exchanges.map(e => e.exchange.toLowerCase());
      return { isSuspicious: names.some(n => ['vpn', 'proxy', 'tor', 'host'].some(k => n.includes(k))), exchanges: names };
    } catch { return { isSuspicious: false, exchanges: [] }; }
  }
  private async checkTXTRecord(ip: string): Promise<{ isSuspicious: boolean; records: string[] }> {
    try {
      const reversed = ip.split('.').reverse().join('.');
      const records = await dnsResolveTxt(`${reversed}.in-addr.arpa`).catch(() => []);
      const txts = records.flat().map(r => r.toLowerCase());
      return { isSuspicious: txts.some(t => ['vpn', 'proxy', 'tor', 'tunnel'].some(k => t.includes(k))), records: txts };
    } catch { return { isSuspicious: false, records: [] }; }
  }
  private async checkNSRecord(ip: string): Promise<{ isSuspicious: boolean; servers: string[] }> {
    try {
      const reversed = ip.split('.').reverse().join('.');
      const servers = await dnsResolveNs(`${reversed}.in-addr.arpa`).catch(() => []);
      const names = servers.map(s => s.toLowerCase());
      return { isSuspicious: names.some(n => ['hosting', 'server', 'cloud', 'vps'].some(k => n.includes(k))), servers: names };
    } catch { return { isSuspicious: false, servers: [] }; }
  }

  // ===== 21 NETWORK/HEAVY METHODS =====
  private async checkOpenPorts(ip: string): Promise<{ isProxy: boolean; openPorts: number[] }> {
    const ports = [1080, 3128, 8080, 9050, 9150];
    const open: number[] = [];
    const check = (port: number): Promise<boolean> => new Promise((resolve) => {
      const s = new net.Socket();
      let resolved = false;
      s.setTimeout(200);
      s.on('connect', () => { if (!resolved) { resolved = true; s.destroy(); resolve(true); } });
      s.on('timeout', () => { if (!resolved) { resolved = true; s.destroy(); resolve(false); } });
      s.on('error', () => { if (!resolved) { resolved = true; resolve(false); } });
      try { s.connect(port, ip); } catch { resolve(false); }
    });
    const results = await Promise.all(ports.map(p => check(p).then(o => ({ port: p, isOpen: o }))));
    for (const r of results) { if (r.isOpen) open.push(r.port); }
    return { isProxy: open.length >= 2, openPorts: open };
  }
  private async checkTTL(ip: string): Promise<{ isSuspicious: boolean; ttl: number }> {
    try {
      const cmd = process.platform === 'win32' ? `ping -n 1 -w 500 ${ip}` : `ping -c 1 -W 1 ${ip}`;
      const out = execSync(cmd, { timeout: 800, encoding: 'utf8', windowsHide: true, stdio: 'pipe' });
      const m = out.match(/ttl[= ](\d+)/i);
      const ttl = m ? parseInt(m[1]) : null;
      if (!ttl) return { isSuspicious: false, ttl: 0 };
      return { isSuspicious: ttl <= 32 || ttl === 63 || ttl === 127 || ttl > 200, ttl };
    } catch { return { isSuspicious: false, ttl: 0 }; }
  }
  private async checkHttpHeaders(ip: string): Promise<{ isProxy: boolean; headers: string[] }> {
    try {
      return new Promise((resolve) => {
        const req = http.get(`http://${ip}:80`, { timeout: 800 }, (res) => {
          const h = res.headers;
          const found: string[] = [];
          if (h['x-forwarded-for']) found.push('X-Forwarded-For');
          if (h['via']) found.push('Via');
          if (h['proxy-connection']) found.push('Proxy-Connection');
          req.destroy();
          resolve({ isProxy: found.length >= 1, headers: found });
        });
        req.on('error', () => resolve({ isProxy: false, headers: [] }));
        req.on('timeout', () => { req.destroy(); resolve({ isProxy: false, headers: [] }); });
      });
    } catch { return { isProxy: false, headers: [] }; }
  }
  private async checkLatency(ip: string): Promise<{ latency: number; isSuspicious: boolean }> {
    try {
      const start = Date.now();
      return new Promise((resolve) => {
        const s = new net.Socket();
        s.setTimeout(800);
        s.on('connect', () => { const lat = Date.now() - start; s.destroy(); resolve({ latency: lat, isSuspicious: lat > 300 }); });
        s.on('timeout', () => { s.destroy(); resolve({ latency: -1, isSuspicious: false }); });
        s.on('error', () => resolve({ latency: -1, isSuspicious: false }));
        s.connect(80, ip);
      });
    } catch { return { latency: -1, isSuspicious: false }; }
  }
  private async checkJA3(ip: string): Promise<{ isVpn: boolean; fingerprint: string }> {
    try {
      return new Promise((resolve) => {
        const s = tls.connect({ host: ip, port: 443, rejectUnauthorized: false, timeout: 800 }, () => {
          const cipher = s.getCipher();
          const fp = cipher?.name || '?';
          s.destroy();
          resolve({ isVpn: ['RC4', 'DES', 'NULL', 'anon'].some(k => fp.includes(k)), fingerprint: fp });
        });
        s.on('error', () => resolve({ isVpn: false, fingerprint: 'error' }));
        s.on('timeout', () => { s.destroy(); resolve({ isVpn: false, fingerprint: 'timeout' }); });
        setTimeout(() => { s.destroy(); resolve({ isVpn: false, fingerprint: 'timeout' }); }, 800);
      });
    } catch { return { isVpn: false, fingerprint: 'error' }; }
  }
  private async checkAbuseIPDB(ip: string): Promise<{ isTor: boolean; isHosting: boolean; score: number }> {
    try {
      const r = await axios.get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, { timeout: 1500, headers: { 'Key': process.env.ABUSEIPDB_KEY || '', 'Accept': 'application/json' } });
      const d = r.data?.data;
      return { isTor: d?.isTor || false, isHosting: (d?.usageType || '').includes('Data Center') || (d?.usageType || '').includes('Hosting'), score: d?.abuseConfidenceScore || 0 };
    } catch { return { isTor: false, isHosting: false, score: 0 }; }
  }
  private async checkBGP(ip: string): Promise<{ isHosting: boolean; asn: string }> {
    try {
      const r = await this.httpClient.get(`https://api.bgpview.io/ip/${ip}`);
      const d = r.data?.data;
      const asn = d?.prefixes?.[0]?.asn?.asn || '';
      const name = (d?.prefixes?.[0]?.asn?.name || '').toLowerCase();
      return { isHosting: ['hosting', 'server', 'cloud', 'vps', 'datacenter', 'digitalocean', 'aws', 'azure', 'google', 'ovh', 'hetzner', 'linode', 'vultr', 'm247', 'choopa'].some(k => name.includes(k)), asn: `AS${asn}` };
    } catch { return { isHosting: false, asn: '' }; }
  }
  private async checkWhois(ip: string): Promise<{ isHosting: boolean; org: string }> {
    try {
      const r = await this.httpClient.get(`https://rdap.arin.net/registry/ip/${ip}`);
      const d = r.data;
      const org = (d?.name || '').toLowerCase();
      return { isHosting: ['hosting', 'server', 'cloud', 'vps', 'datacenter'].some(k => org.includes(k)), org };
    } catch { return { isHosting: false, org: '' }; }
  }
  private async checkWebRTC(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> {
    try { const r = await this.httpClient.get(`https://api.webrtc-leak.com/check/${ip}`); return { isVpn: r.data?.vpn || false, isProxy: r.data?.proxy || false }; } catch { return { isVpn: false, isProxy: false }; }
  }
  private async checkDNSLeak(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> {
    try { const r = await this.httpClient.get(`https://api.dnsleaktest.com/check/${ip}`); return { isVpn: r.data?.vpn || false, isProxy: r.data?.proxy || false }; } catch { return { isVpn: false, isProxy: false }; }
  }
  private async checkProxyCheck(ip: string): Promise<{ isVpn: boolean; isProxy: boolean; isTor: boolean; isHosting: boolean }> {
    try {
      const r = await this.httpClient.get(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1`);
      const d = r.data?.[ip] || {};
      return { isVpn: d?.proxy === 'yes' || d?.vpn === 'yes', isProxy: d?.proxy === 'yes', isTor: d?.type === 'Tor', isHosting: d?.type === 'Data Center' };
    } catch { return { isVpn: false, isProxy: false, isTor: false, isHosting: false }; }
  }
  private async checkIPQuality(ip: string): Promise<{ isVpn: boolean; isProxy: boolean; isTor: boolean; isHosting: boolean }> {
    try {
      const r = await this.httpClient.get(`https://ipqualityscore.com/api/json/ip/${process.env.IPQUALITY_KEY || ''}/${ip}`);
      const d = r.data || {};
      return { isVpn: d?.vpn || false, isProxy: d?.proxy || false, isTor: d?.tor || false, isHosting: d?.is_crawler || d?.recent_abuse || false };
    } catch { return { isVpn: false, isProxy: false, isTor: false, isHosting: false }; }
  }
  private async checkVpnApi(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> {
    try { const r = await this.httpClient.get(`https://vpnapi.io/api/${ip}?key=${process.env.VPNAPI_KEY || ''}`); const d = r.data?.security || {}; return { isVpn: d?.vpn || false, isProxy: d?.proxy || false }; } catch { return { isVpn: false, isProxy: false }; }
  }
  private async checkIPIntel(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> {
    try { const r = await this.httpClient.get(`https://ip-intel.xyz/api/check?ip=${ip}`); const d = r.data || {}; return { isVpn: d?.vpn || d?.proxy || false, isProxy: d?.proxy || false }; } catch { return { isVpn: false, isProxy: false }; }
  }
  private async checkIPRegistry(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> {
    try { const r = await this.httpClient.get(`https://api.ipregistry.co/${ip}?key=${process.env.IPREGISTRY_KEY || ''}`); const d = r.data?.security || {}; return { isVpn: d?.is_vpn || d?.is_proxy || false, isProxy: d?.is_proxy || false }; } catch { return { isVpn: false, isProxy: false }; }
  }
  private async checkGRETunnel(ip: string): Promise<boolean> {
    try { return new Promise((resolve) => { const s = net.createConnection({ host: ip, port: 47, timeout: 500 }, () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); s.on('timeout', () => { s.destroy(); resolve(false); }); }); } catch { return false; }
  }
  private async checkSYNFlood(ip: string): Promise<{ isProxy: boolean }> {
    try {
      return new Promise((resolve) => {
        const s = new net.Socket(); s.setTimeout(500);
        s.on('connect', () => { s.destroy(); resolve({ isProxy: true }); });
        s.on('error', () => resolve({ isProxy: false }));
        s.on('timeout', () => { s.destroy(); resolve({ isProxy: false }); });
        s.connect(443, ip);
      });
    } catch { return { isProxy: false }; }
  }
  private async checkICMPResponse(ip: string): Promise<{ isSuspicious: boolean; response: string }> {
    try {
      const cmd = process.platform === 'win32' ? `ping -n 1 -w 500 ${ip}` : `ping -c 1 -W 1 ${ip}`;
      const out = execSync(cmd, { timeout: 800, encoding: 'utf8', windowsHide: true, stdio: 'pipe' });
      return { isSuspicious: out.includes('Request timed out') || out.includes('100% packet loss'), response: out.includes('bytes from') ? 'responsive' : 'no response' };
    } catch { return { isSuspicious: false, response: 'error' }; }
  }
  private async checkHTTPFingerprint(ip: string): Promise<{ isProxy: boolean; server: string }> {
    try {
      return new Promise((resolve) => {
        const req = http.get(`http://${ip}`, { timeout: 800 }, (res) => {
          const server = (Array.isArray(res.headers['server']) ? res.headers['server'][0] : res.headers['server'] || '').toLowerCase();
          resolve({ isProxy: ['squid', 'haproxy', 'nginx', 'varnish', 'privoxy', 'polipo', 'tinyproxy', '3proxy'].some(k => server.includes(k)), server });
          req.destroy();
        });
        req.on('error', () => resolve({ isProxy: false, server: '' }));
        req.on('timeout', () => { req.destroy(); resolve({ isProxy: false, server: '' }); });
      });
    } catch { return { isProxy: false, server: '' }; }
  }
  private async checkTLSFingerprint(ip: string): Promise<{ isVpn: boolean; cipher: string }> {
    try {
      return new Promise((resolve) => {
        const s = tls.connect({ host: ip, port: 443, rejectUnauthorized: false, timeout: 800 }, () => {
          const cert = s.getPeerCertificate();
          const issuer = (typeof cert?.issuer?.O === 'string' ? cert.issuer.O : '').toLowerCase();
          const subject = (typeof cert?.subject?.O === 'string' ? cert.subject.O : '').toLowerCase();
          resolve({ isVpn: ['vpn', 'proxy', 'tor'].some(k => issuer.includes(k) || subject.includes(k)), cipher: s.getCipher()?.name || '' });
          s.destroy();
        });
        s.on('error', () => resolve({ isVpn: false, cipher: '' }));
        s.on('timeout', () => { s.destroy(); resolve({ isVpn: false, cipher: '' }); });
        setTimeout(() => { s.destroy(); resolve({ isVpn: false, cipher: '' }); }, 800);
      });
    } catch { return { isVpn: false, cipher: '' }; }
  }
  private async checkSNICheck(ip: string): Promise<{ isVpn: boolean; sni: string }> {
    try {
      return new Promise((resolve) => {
        const s = tls.connect({ host: ip, port: 443, servername: 'google.com', rejectUnauthorized: false, timeout: 800 }, () => { resolve({ isVpn: false, sni: s.servername || '' }); s.destroy(); });
        s.on('error', () => resolve({ isVpn: false, sni: '' }));
        s.on('timeout', () => { s.destroy(); resolve({ isVpn: false, sni: '' }); });
        setTimeout(() => { s.destroy(); resolve({ isVpn: false, sni: '' }); }, 800);
      });
    } catch { return { isVpn: false, sni: '' }; }
  }

  // ===== HELPERS =====
  private checkSuspiciousRanges(ip: string): string | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return null;
    for (const range of this.suspiciousRanges) {
      const rp = range.range.split('.').map(Number);
      let match = true;
      for (let i = 0; i < Math.floor(range.mask / 8); i++) {
        if (parts[i] !== rp[i]) { match = false; break; }
      }
      if (match) return range.reason;
    }
    return null;
  }
  private hasInstantBanKeyword(normalizedProvider: string): boolean {
    for (const keyword of INSTANT_BAN_KEYWORDS) {
      const normalized = this.normalizeProviderText(keyword);
      if (normalized.length >= 4 && normalizedProvider.includes(normalized)) return true;
    }
    return false;
  }
  private matchesKeywords(normalizedProvider: string, keywords: string[]): boolean {
    for (const keyword of keywords) {
      const normalized = this.normalizeProviderText(keyword);
      if (normalized.length >= 4 && normalizedProvider.includes(normalized)) return true;
    }
    return false;
  }
  private isTrustedProvider(providerText: string): boolean {
    const normalized = this.normalizeProviderText(providerText);
    for (const trusted of TRUSTED_PROVIDERS) {
      if (normalized.includes(trusted)) return true;
    }
    return false;
  }
  private normalizeProviderText(text: string): string {
    return (text || '').toLowerCase().replace(/[^a-z0-9]+/gi, ' ').replace(/\s+/g, ' ').trim();
  }
  private createBanResult(ip: string, info: { country: string; city: string; isp: string; org: string }, score: number): IpCheckResult {
    return { ip, is_vpn: true, is_proxy: true, is_hosting: true, is_tor: false, is_datacenter: true, country: info.country, city: info.city, isp: info.isp, organization: info.org, risk_score: score, threat_level: 'critical', checked_at: new Date().toISOString(), cached: false };
  }
  private createVpnResult(ip: string, info: { country: string; city: string; isp: string; org: string }): IpCheckResult {
    return { ip, is_vpn: true, is_proxy: false, is_hosting: false, is_tor: false, is_datacenter: false, country: info.country, city: info.city, isp: info.isp, organization: info.org, risk_score: 85, threat_level: 'high', checked_at: new Date().toISOString(), cached: false };
  }
  private createProxyResult(ip: string, info: { country: string; city: string; isp: string; org: string }): IpCheckResult {
    return { ip, is_vpn: false, is_proxy: true, is_hosting: false, is_tor: false, is_datacenter: false, country: info.country, city: info.city, isp: info.isp, organization: info.org, risk_score: 75, threat_level: 'medium', checked_at: new Date().toISOString(), cached: false };
  }
  private createHostingResult(ip: string, info: { country: string; city: string; isp: string; org: string }): IpCheckResult {
    return { ip, is_vpn: false, is_proxy: false, is_hosting: true, is_tor: false, is_datacenter: true, country: info.country, city: info.city, isp: info.isp, organization: info.org, risk_score: 65, threat_level: 'medium', checked_at: new Date().toISOString(), cached: false };
  }
  private createDatacenterResult(ip: string, info: { country: string; city: string; isp: string; org: string }): IpCheckResult {
    return { ip, is_vpn: false, is_proxy: false, is_hosting: false, is_tor: false, is_datacenter: true, country: info.country, city: info.city, isp: info.isp, organization: info.org, risk_score: 60, threat_level: 'low', checked_at: new Date().toISOString(), cached: false };
  }
  private createCleanResult(ip: string, country: string, city: string, isp: string, org: string): IpCheckResult {
    return { ip, is_vpn: false, is_proxy: false, is_hosting: false, is_tor: false, is_datacenter: false, country, city, isp, organization: org, risk_score: 0, threat_level: 'low', checked_at: new Date().toISOString(), cached: false };
  }
  getStats(): { cache_size: number; ml_samples: number; ml_accuracy: number } {
    const mlStats = this.mlDetector.getStats();
    return { cache_size: Object.keys(this.cache.getAll()).length, ml_samples: mlStats.samples, ml_accuracy: mlStats.accuracy };
  }
}