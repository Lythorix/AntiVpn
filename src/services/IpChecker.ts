// src/services/IpChecker.ts
import axios, { AxiosInstance } from 'axios';
import { IpCheckResult, AppConfig } from '../types';
import { CacheService } from '../utils/Cache';
import { Logger } from '../utils/Logger';
import { ListManager } from './ListManager';
import { VPN_KEYWORDS, DATACENTER_KEYWORDS, PROXY_KEYWORDS, HOSTING_KEYWORDS, TRUSTED_PROVIDERS } from './ProviderLists';
import * as dns from 'dns';
import { promisify } from 'util';
import * as net from 'net';
import * as http from 'http';
import * as tls from 'tls';

const dnsReverse = promisify(dns.reverse);

export class IpChecker {
  private static instance: IpChecker;
  private httpClient: AxiosInstance;
  private cache: CacheService;
  private listManager: ListManager;
  private logger: Logger;
  private config: AppConfig;
  private lastCheckTime: number = 0;

  // Оставляем 2 — это оптимально для детекта
  private readonly MIN_API_VOTES_VPN = 2;
  private readonly MIN_API_VOTES_PROXY = 2;
  private readonly MIN_API_VOTES_HOSTING = 2;

  private vpnCheckApis = [
    {
      name: 'ip-api.com',
      url: 'http://ip-api.com/json/{ip}?fields=country,countryCode,region,regionName,city,isp,org,as,proxy,hosting,query',
      parse: (data: any) => ({
        country: data.country || null, city: data.city || null,
        isp: data.isp || null, org: data.org || data.isp || null,
        isProxy: data.proxy || false, isHosting: data.hosting || false
      })
    },
    {
      name: 'ipwhois.io',
      url: 'https://ipwhois.app/json/{ip}',
      parse: (data: any) => ({
        country: data.country || null, city: data.city || null,
        isp: data.isp || null, org: data.org || data.isp || null,
        isVpn: data.type === 'VPN',
        isProxy: data.type === 'Proxy',
        isHosting: data.type === 'Hosting'
      })
    },
    {
      name: 'ipapi.co',
      url: 'https://ipapi.co/{ip}/json/',
      parse: (data: any) => ({
        country: data.country_name || null, city: data.city || null,
        isp: data.org || null, org: data.org || null,
        isHosting: data.asn?.type === 'hosting'
      })
    },
    {
      name: 'freeipapi.com',
      url: 'https://freeipapi.com/api/json/{ip}',
      parse: (data: any) => ({
        country: data.countryName || null, city: data.cityName || null,
        isp: data.isp || null, org: data.isp || null,
        isVpn: data.isVpn || false,
        isProxy: data.isProxy || false,
        isTor: data.isTor || false
      })
    },
    {
      name: 'ipinfo.io',
      url: 'https://ipinfo.io/{ip}/json',
      parse: (data: any) => ({
        country: data.country || null, city: data.city || null,
        isp: data.org || null, org: data.org || data.company?.name || null,
        isVpn: data.privacy?.vpn || false,
        isProxy: data.privacy?.proxy || false,
        isTor: data.privacy?.tor || false,
        isHosting: data.privacy?.hosting || false
      })
    }
  ];

  private vpnKeywords: string[] = VPN_KEYWORDS;
  private datacenterKeywords: string[] = DATACENTER_KEYWORDS;
  private proxyKeywords: string[] = PROXY_KEYWORDS;
  private hostingKeywords: string[] = HOSTING_KEYWORDS;
  private trustedProviders: string[] = TRUSTED_PROVIDERS;

  private suspiciousRanges = [
    { range: '185.220.100.0', mask: 24, reason: 'TOR Exit Node' },
    { range: '185.220.101.0', mask: 24, reason: 'TOR Exit Node' },
    { range: '146.70.0.0', mask: 16, reason: 'M247 VPN/Hosting' },
  ];

  private playerBehaviorCache: Map<string, { 
    ips: string[]; countries: string[]; firstSeen: number; lastSeen: number; ipChanges: number;
    latencyHistory: number[];
  }> = new Map();

  private constructor(config: AppConfig) {
    this.config = config;
    this.logger = Logger.getInstance();
    this.cache = CacheService.getInstance();
    this.listManager = ListManager.getInstance();
    this.httpClient = axios.create({
      timeout: 8000,
      headers: { 'User-Agent': 'LythorixAntiVpn/3.0', 'Accept': 'application/json' }
    });
  }

  static getInstance(config?: AppConfig): IpChecker {
    if (!IpChecker.instance) {
      if (!config) throw new Error('Config required');
      IpChecker.instance = new IpChecker(config);
    }
    return IpChecker.instance;
  }

  async checkIp(ip: string, playerName?: string): Promise<IpCheckResult> {
    // 1. МГНОВЕННЫЕ ПРОВЕРКИ
    if (this.listManager.isWhitelisted(ip)) return this.createCleanResult(ip, 'Whitelisted', '', '', '');
    if (this.listManager.isPrivateIP(ip)) return this.createLocalResult(ip);
    if (this.listManager.isBlacklisted(ip)) {
      return { ip, is_vpn: true, is_proxy: true, is_hosting: true, is_tor: false, is_datacenter: true, country: 'Blacklisted', city: '', isp: '', organization: '', risk_score: 100, threat_level: 'critical', checked_at: new Date().toISOString(), cached: false };
    }
    const cached = this.cache.get(ip);
    if (cached) return cached;

    const rangeCheck = this.checkSuspiciousRanges(ip);
    if (rangeCheck) {
      const result = this.createSuspiciousResult(ip, rangeCheck);
      this.cache.set(ip, result);
      this.listManager.addToBlacklist(ip, `Known range: ${rangeCheck}`, 'Range DB');
      return result;
    }

    // 2. ВСЕ 17 ПРОВЕРОК ПАРАЛЛЕЛЬНО
    const [
      apiResults, reverseDnsCheck, portCheck, ttlCheck,
      httpHeadersCheck, latencyCheck, ja3Check, abuseIpDbCheck,
      bgpCheck, whoisCheck, webRtcCheck, dnsLeakCheck,
      proxyCheck, ipQualityCheck, vpnApiCheck, ipIntelCheck, ipRegistryCheck
    ] = await Promise.all([
      Promise.allSettled(this.vpnCheckApis.map(api => this.checkWithApi(api, ip))),
      this.checkReverseDNS(ip),
      this.checkOpenPorts(ip),
      this.checkTTL(ip),
      this.checkHttpHeaders(ip),
      this.checkLatency(ip),
      this.checkJA3(ip),
      this.checkAbuseIPDB(ip),
      this.checkBGP(ip),
      this.checkWhois(ip),
      this.checkWebRTC(ip),
      this.checkDNSLeak(ip),
      this.checkProxyCheck(ip),
      this.checkIPQuality(ip),
      this.checkVpnApi(ip),
      this.checkIPIntel(ip),
      this.checkIPRegistry(ip),
    ]);

    // 3. ПОВЕДЕНЧЕСКИЙ АНАЛИЗ
    let behavioralScore = 0;
    const behavioralReasons: string[] = [];
    if (playerName) {
      const now = Date.now();
      const behavior = this.playerBehaviorCache.get(playerName) || { ips: [], countries: [], firstSeen: now, lastSeen: now, ipChanges: 0, latencyHistory: [] };
      if (behavior.countries.length >= 2) { behavioralScore += 30; behavioralReasons.push('GeoJump'); }
      if (!behavior.ips.includes(ip)) { behavior.ips.push(ip); behavior.ipChanges++; if (behavior.ips.length > 5) { behavioralScore += 50; behavioralReasons.push(`MultiIP:${behavior.ips.length}`); } else if (behavior.ips.length > 3) { behavioralScore += 25; behavioralReasons.push(`MultiIP:${behavior.ips.length}`); } }
      const timeSinceFirstSeen = now - behavior.firstSeen;
      if (timeSinceFirstSeen < 300000 && behavior.ipChanges >= 3) { behavioralScore += 40; behavioralReasons.push('RapidIPChange'); }
      if (behavior.ipChanges >= 5 && timeSinceFirstSeen < 600000) { behavioralScore += 60; behavioralReasons.push('BotPattern'); }
      if (latencyCheck.latency > 0 && latencyCheck.latency > 300) { behavioralScore += 20; behavioralReasons.push('HighLatency'); }
      behavior.lastSeen = now;
      this.playerBehaviorCache.set(playerName, behavior);
      if (now - behavior.firstSeen > 3600000) this.playerBehaviorCache.delete(playerName);
    }

    // 4. API ПРОВЕРКИ
    let apiVpnVotes = 0, apiProxyVotes = 0, apiTorVotes = 0, apiHostingVotes = 0, totalApis = 0;
    let allCountries: string[] = [], allCities: string[] = [], allIsps: string[] = [], allOrgs: string[] = [];
    for (const r of apiResults) {
      if (r.status === 'fulfilled' && r.value) {
        totalApis++;
        const d = r.value;
        if (d.country && d.country !== 'Unknown') allCountries.push(d.country);
        if (d.city && d.city !== 'Unknown') allCities.push(d.city);
        if (d.isp && d.isp !== 'Unknown') allIsps.push(d.isp);
        if (d.org && d.org !== 'Unknown') allOrgs.push(d.org);
        if (d.isVpn) apiVpnVotes++; if (d.isProxy) apiProxyVotes++; if (d.isTor) apiTorVotes++; if (d.isHosting) apiHostingVotes++;
      }
    }

    const finalIsp = allIsps[0] || 'Unknown';
    const finalOrg = allOrgs[0] || finalIsp;
    const finalCountry = allCountries[0] || 'Unknown';
    const finalCity = allCities[0] || 'Unknown';
    if (playerName && finalCountry !== 'Unknown') { const behavior = this.playerBehaviorCache.get(playerName); if (behavior && !behavior.countries.includes(finalCountry)) { behavior.countries.push(finalCountry); if (behavior.countries.length > 10) behavior.countries.shift(); } }

    const ispLower = finalIsp.toLowerCase().trim();
    const orgLower = finalOrg.toLowerCase().trim();
    const combined = `${ispLower} ${orgLower}`;

    // 5. АНТИ-ЛОЖНЫЙ БАН: ТРИ УРОВНЯ
    const isCityMatch = finalCity !== 'Unknown' && finalCity !== '' && (ispLower.includes(finalCity.toLowerCase()) || orgLower.includes(finalCity.toLowerCase()));
    if (isCityMatch) { const cr = this.createCleanResult(ip, finalCountry, finalCity, finalIsp, finalOrg); this.cache.set(ip, cr); this.listManager.addToWhitelist(ip, `Local ISP: ${finalIsp}`); return cr; }

    const telecomSuffixes = ['telecom', 'telecommunications', 'broadband', 'fiber', 'fibre', 'wireless', 'mobile', 'telephone', 'phone', 'cellular', 'dsl', 'isp', 'internet provider'];
    const isTelecom = telecomSuffixes.some(s => ispLower.includes(s) || orgLower.includes(s));
    if (isTelecom) { const cr = this.createCleanResult(ip, finalCountry, finalCity, finalIsp, finalOrg); this.cache.set(ip, cr); this.listManager.addToWhitelist(ip, `Telecom ISP: ${finalIsp}`); return cr; }

    const isTrusted = this.trustedProviders.some(tp => ispLower.includes(tp) || orgLower.includes(tp));
    if (isTrusted || this.listManager.isWhitelistedByProvider(finalIsp, finalOrg)) { const cr = this.createCleanResult(ip, finalCountry, finalCity, finalIsp, finalOrg); this.cache.set(ip, cr); this.listManager.addToWhitelist(ip, `Trusted ISP: ${finalIsp}`); return cr; }

    // 6. КЛЮЧЕВЫЕ СЛОВА
    const isVpnByKeyword = this.vpnKeywords.some(k => combined.includes(k));
    const isProxyByKeyword = this.proxyKeywords.some(k => combined.includes(k));
    const isDatacenterByKeyword = this.datacenterKeywords.some(k => combined.includes(k));
    const isHostingByKeyword = this.hostingKeywords.some(k => combined.includes(k));

    // 7. ФИНАЛЬНОЕ РЕШЕНИЕ (ВСЕ 17 МЕТОДОВ)
    const isVpn = (apiVpnVotes >= this.MIN_API_VOTES_VPN) || reverseDnsCheck.isVpn || isVpnByKeyword || ttlCheck.isSuspicious || ja3Check.isVpn || webRtcCheck.isVpn || dnsLeakCheck.isVpn || httpHeadersCheck.isProxy || bgpCheck.isHosting || whoisCheck.isHosting || proxyCheck.isVpn || ipQualityCheck.isVpn || vpnApiCheck.isVpn || ipIntelCheck.isVpn || ipRegistryCheck.isVpn;
    const isProxy = (apiProxyVotes >= this.MIN_API_VOTES_PROXY) || portCheck.isProxy || isProxyByKeyword || httpHeadersCheck.isProxy || webRtcCheck.isProxy || dnsLeakCheck.isProxy || proxyCheck.isProxy || ipQualityCheck.isProxy || vpnApiCheck.isProxy || ipIntelCheck.isProxy || ipRegistryCheck.isProxy;
    const isTor = (apiTorVotes >= 1) || abuseIpDbCheck.isTor || proxyCheck.isTor || ipQualityCheck.isTor;
    const isHosting = isHostingByKeyword || (apiHostingVotes >= this.MIN_API_VOTES_HOSTING) || reverseDnsCheck.isHosting || bgpCheck.isHosting || whoisCheck.isHosting || abuseIpDbCheck.isHosting || proxyCheck.isHosting || ipQualityCheck.isHosting;
    const isDatacenter = isDatacenterByKeyword || isHosting;
    const isSuspiciousBehavior = behavioralScore >= 60;

    // 8. RISK SCORE
    let riskScore = 0;
    if (isTor || isSuspiciousBehavior) riskScore = 100;
    else if (isVpn && isProxy) riskScore = 95;
    else if (isVpn) riskScore = 80;
    else if (isProxy) riskScore = 70;
    else if (isHosting || isDatacenter) riskScore = 45;
    if (portCheck.isProxy && riskScore < 70) riskScore = 70;
    if (reverseDnsCheck.isVpn && riskScore < 70) riskScore = 70;
    if (ttlCheck.isSuspicious && riskScore < 60) riskScore = 60;
    if (ja3Check.isVpn && riskScore < 80) riskScore = 80;
    if (httpHeadersCheck.isProxy && riskScore < 70) riskScore = 70;
    if (webRtcCheck.isVpn && riskScore < 80) riskScore = 80;
    if (dnsLeakCheck.isVpn && riskScore < 70) riskScore = 70;
    if (bgpCheck.isHosting && riskScore < 60) riskScore = 60;
    if (whoisCheck.isHosting && riskScore < 60) riskScore = 60;
    if (proxyCheck.isVpn && riskScore < 80) riskScore = 80;
    if (ipQualityCheck.isVpn && riskScore < 80) riskScore = 80;
    if (vpnApiCheck.isVpn && riskScore < 80) riskScore = 80;
    if (ipIntelCheck.isVpn && riskScore < 80) riskScore = 80;
    if (ipRegistryCheck.isVpn && riskScore < 80) riskScore = 80;
    if (behavioralScore >= 30 && riskScore < 50) riskScore = 50;
    if (behavioralScore >= 60 && riskScore < 90) riskScore = 90;

    const threatLevel = (isTor || isSuspiciousBehavior) ? 'critical' : isVpn ? 'high' : isProxy ? 'medium' : (isHosting || isDatacenter) ? 'low' : 'low';

    const finalResult: IpCheckResult = { ip, is_vpn: isVpn, is_proxy: isProxy, is_tor: isTor, is_hosting: isHosting, is_datacenter: isDatacenter, country: finalCountry, city: finalCity, isp: finalIsp, organization: finalOrg, risk_score: riskScore, threat_level: threatLevel, checked_at: new Date().toISOString(), cached: false };
    this.cache.set(ip, finalResult);

    const isSuspicious = isVpn || isProxy || isTor || isHosting || isDatacenter || isSuspiciousBehavior;
    if (isSuspicious) {
      const reasons = [];
      if (isVpn) reasons.push(`VPN(${apiVpnVotes}/${totalApis})`);
      if (isProxy) reasons.push(`Proxy(${apiProxyVotes}/${totalApis})`);
      if (isTor) reasons.push('TOR');
      if (isHosting) reasons.push(`Hosting(${apiHostingVotes}/${totalApis})`);
      if (portCheck.isProxy) reasons.push(`Ports:${portCheck.openPorts.join(',')}`);
      if (reverseDnsCheck.isVpn) reasons.push(`rDNS:${reverseDnsCheck.hostname}`);
      if (ttlCheck.isSuspicious) reasons.push(`TTL:${ttlCheck.ttl}`);
      if (ja3Check.isVpn) reasons.push(`JA3:${ja3Check.fingerprint}`);
      if (httpHeadersCheck.isProxy) reasons.push('Headers:proxy');
      if (webRtcCheck.isVpn) reasons.push('WebRTC:leak');
      if (dnsLeakCheck.isVpn) reasons.push('DNS:leak');
      if (bgpCheck.isHosting) reasons.push(`BGP:${bgpCheck.asn}`);
      if (whoisCheck.isHosting) reasons.push('WHOIS:hosting');
      if (abuseIpDbCheck.isTor) reasons.push('AbuseIPDB:TOR');
      if (proxyCheck.isVpn) reasons.push('ProxyCheck:VPN');
      if (ipQualityCheck.isVpn) reasons.push('IPQuality:VPN');
      if (vpnApiCheck.isVpn) reasons.push('VPNApi:YES');
      if (ipIntelCheck.isVpn) reasons.push('IPIntel:VPN');
      if (ipRegistryCheck.isVpn) reasons.push('IPRegistry:VPN');
      if (behavioralScore >= 60) reasons.push(`Behavior:${behavioralReasons.join(';')}`);
      this.listManager.addToBlacklist(ip, reasons.join('+'), `${totalApis} APIs`);
      this.logger.warn(`⛔ SUSPICIOUS: ${ip} - ${reasons.join('+')} [${riskScore}] ${finalIsp} | ${finalOrg}`);
    } else {
      this.listManager.addToWhitelist(ip, 'Clean');
      this.logger.info(`✅ CLEAN: ${ip} [${finalCountry}, ${finalIsp}]`);
    }
    return finalResult;
  }

  // ====== ВСЕ 17 МЕТОДОВ ======
  private async checkReverseDNS(ip: string): Promise<{ isVpn: boolean; isHosting: boolean; hostname: string }> {
    try { const hostnames = await dnsReverse(ip); const hostname = hostnames[0] || ''; const lower = hostname.toLowerCase(); return { isVpn: ['vpn','proxy','tor','socks','tunnel','relay','anon'].some(k => lower.includes(k)), isHosting: ['vps','host','server','cloud','dedicated','colo','dc','datacenter','node','cluster'].some(k => lower.includes(k)), hostname }; } catch (e) { return { isVpn: false, isHosting: false, hostname: '' }; }
  }
  private async checkOpenPorts(ip: string): Promise<{ isProxy: boolean; openPorts: number[] }> {
    const ports = [1080, 3128, 8080, 8888, 9050, 9150]; const open: number[] = [];
    const check = (port: number): Promise<boolean> => new Promise((resolve) => { const s = new net.Socket(); let r = false; s.setTimeout(800); s.on('connect', () => { if (!r) { r = true; s.destroy(); resolve(true); } }); s.on('timeout', () => { if (!r) { r = true; s.destroy(); resolve(false); } }); s.on('error', () => { if (!r) { r = true; resolve(false); } }); try { s.connect(port, ip); } catch (e) { if (!r) { r = true; resolve(false); } } });
    const results = await Promise.all(ports.map(p => check(p).then(o => ({ port: p, isOpen: o }))));
    for (const r of results) { if (r.isOpen) open.push(r.port); }
    return { isProxy: open.length >= 2, openPorts: open };
  }
  private async checkTTL(ip: string): Promise<{ isSuspicious: boolean; ttl: number; expectedRange: string }> {
    try { const { execSync } = require('child_process'); const cmd = process.platform === 'win32' ? `ping -n 1 -w 1500 ${ip}` : `ping -c 1 -W 2 ${ip}`; const out = execSync(cmd, { timeout: 2000, encoding: 'utf8', windowsHide: true, stdio: 'pipe' }); const m = out.match(/ttl[= ](\d+)/i); const ttl = m ? parseInt(m[1]) : null; if (!ttl) return { isSuspicious: false, ttl: 0, expectedRange: 'unknown' }; let sus = false, exp = ''; if (ttl <= 32) { sus = true; exp = '64-255'; } else if (ttl === 63) { sus = true; exp = '64'; } else if (ttl === 127) { sus = true; exp = '128'; } else if (ttl > 200) { sus = true; exp = '64-128'; } return { isSuspicious: sus, ttl, expectedRange: exp }; } catch (e) { return { isSuspicious: false, ttl: 0, expectedRange: 'error' }; }
  }
  private async checkHttpHeaders(ip: string): Promise<{ isProxy: boolean; headers: string[] }> {
    try { return new Promise((resolve) => { const req = http.get(`http://${ip}:80`, { timeout: 2000 }, (res) => { const h = res.headers; const found: string[] = []; if (h['x-forwarded-for']) found.push('X-Forwarded-For'); if (h['via']) found.push('Via'); if (h['proxy-connection']) found.push('Proxy-Connection'); req.destroy(); resolve({ isProxy: found.length >= 1, headers: found }); }); req.on('error', () => resolve({ isProxy: false, headers: [] })); req.on('timeout', () => { req.destroy(); resolve({ isProxy: false, headers: [] }); }); }); } catch (e) { return { isProxy: false, headers: [] }; }
  }
  private async checkLatency(ip: string): Promise<{ latency: number; isSuspicious: boolean }> { try { const start = Date.now(); return new Promise((resolve) => { const s = new net.Socket(); s.setTimeout(2000); s.on('connect', () => { const lat = Date.now() - start; s.destroy(); resolve({ latency: lat, isSuspicious: lat > 300 }); }); s.on('timeout', () => { s.destroy(); resolve({ latency: -1, isSuspicious: false }); }); s.on('error', () => resolve({ latency: -1, isSuspicious: false })); s.connect(80, ip); }); } catch (e) { return { latency: -1, isSuspicious: false }; } }
  private async checkJA3(ip: string): Promise<{ isVpn: boolean; fingerprint: string }> { try { return new Promise((resolve) => { const s = tls.connect({ host: ip, port: 443, rejectUnauthorized: false, timeout: 2000 }, () => { const cipher = s.getCipher(); const protocol = s.getProtocol(); const isVpn = cipher?.name?.includes('CHACHA20') || cipher?.name?.includes('AES_256_GCM'); s.destroy(); resolve({ isVpn, fingerprint: `${cipher?.name || '?'}-${protocol || '?'}` }); }); s.on('error', () => resolve({ isVpn: false, fingerprint: 'error' })); s.on('timeout', () => { s.destroy(); resolve({ isVpn: false, fingerprint: 'timeout' }); }); setTimeout(() => { s.destroy(); resolve({ isVpn: false, fingerprint: 'timeout' }); }, 2000); }); } catch (e) { return { isVpn: false, fingerprint: 'error' }; } }
  private async checkAbuseIPDB(ip: string): Promise<{ isTor: boolean; isHosting: boolean; score: number }> { try { const r = await axios.get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, { timeout: 3000, headers: { 'Key': process.env.ABUSEIPDB_KEY || '', 'Accept': 'application/json' } }); const d = r.data?.data; return { isTor: d?.isTor || false, isHosting: (d?.usageType || '').includes('Data Center') || (d?.usageType || '').includes('Hosting'), score: d?.abuseConfidenceScore || 0 }; } catch (e) { return { isTor: false, isHosting: false, score: 0 }; } }
  private async checkBGP(ip: string): Promise<{ isHosting: boolean; asn: string }> { try { const r = await axios.get(`https://api.bgpview.io/ip/${ip}`, { timeout: 3000 }); const d = r.data?.data; const asn = d?.prefixes?.[0]?.asn?.asn || ''; const name = (d?.prefixes?.[0]?.asn?.name || '').toLowerCase(); return { isHosting: ['hosting','server','cloud','vps','datacenter','digitalocean','aws','azure','google','ovh','hetzner','linode','vultr','choopa'].some(k => name.includes(k)), asn: `AS${asn}` }; } catch (e) { return { isHosting: false, asn: '' }; } }
  private async checkWhois(ip: string): Promise<{ isHosting: boolean; org: string }> { try { const r = await axios.get(`https://rdap.arin.net/registry/ip/${ip}`, { timeout: 3000 }); const d = r.data; const org = (d?.name || '').toLowerCase(); return { isHosting: ['hosting','server','cloud','vps','datacenter','digitalocean','aws','azure','google','ovh','hetzner','linode','vultr'].some(k => org.includes(k)), org }; } catch (e) { return { isHosting: false, org: '' }; } }
  private async checkWebRTC(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> { try { const r = await axios.get(`https://api.webrtc-leak.com/check/${ip}`, { timeout: 3000 }); return { isVpn: r.data?.vpn || false, isProxy: r.data?.proxy || false }; } catch (e) { return { isVpn: false, isProxy: false }; } }
  private async checkDNSLeak(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> { try { const r = await axios.get(`https://api.dnsleaktest.com/check/${ip}`, { timeout: 3000 }); return { isVpn: r.data?.vpn || false, isProxy: r.data?.proxy || false }; } catch (e) { return { isVpn: false, isProxy: false }; } }
  private async checkProxyCheck(ip: string): Promise<{ isVpn: boolean; isProxy: boolean; isTor: boolean; isHosting: boolean }> { try { const r = await axios.get(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1`, { timeout: 3000 }); const d = r.data?.[ip] || {}; return { isVpn: d?.proxy === 'yes' || d?.vpn === 'yes', isProxy: d?.proxy === 'yes', isTor: d?.type === 'Tor', isHosting: d?.type === 'Data Center' }; } catch (e) { return { isVpn: false, isProxy: false, isTor: false, isHosting: false }; } }
  private async checkIPQuality(ip: string): Promise<{ isVpn: boolean; isProxy: boolean; isTor: boolean; isHosting: boolean }> { try { const r = await axios.get(`https://ipqualityscore.com/api/json/ip/${process.env.IPQUALITY_KEY || ''}/${ip}`, { timeout: 3000 }); const d = r.data || {}; return { isVpn: d?.vpn || false, isProxy: d?.proxy || false, isTor: d?.tor || false, isHosting: d?.is_crawler || d?.recent_abuse || false }; } catch (e) { return { isVpn: false, isProxy: false, isTor: false, isHosting: false }; } }
  private async checkVpnApi(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> { try { const r = await axios.get(`https://vpnapi.io/api/${ip}?key=${process.env.VPNAPI_KEY || ''}`, { timeout: 3000 }); const d = r.data?.security || {}; return { isVpn: d?.vpn || false, isProxy: d?.proxy || false }; } catch (e) { return { isVpn: false, isProxy: false }; } }
  private async checkIPIntel(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> { try { const r = await axios.get(`https://ip-intel.xyz/api/check?ip=${ip}`, { timeout: 3000 }); const d = r.data || {}; return { isVpn: d?.vpn || d?.proxy || false, isProxy: d?.proxy || false }; } catch (e) { return { isVpn: false, isProxy: false }; } }
  private async checkIPRegistry(ip: string): Promise<{ isVpn: boolean; isProxy: boolean }> { try { const r = await axios.get(`https://api.ipregistry.co/${ip}?key=${process.env.IPREGISTRY_KEY || ''}`, { timeout: 3000 }); const d = r.data?.security || {}; return { isVpn: d?.is_vpn || d?.is_proxy || false, isProxy: d?.is_proxy || false }; } catch (e) { return { isVpn: false, isProxy: false }; } }
  private async checkWithApi(api: any, ip: string): Promise<any | null> { try { const url = api.url.replace('{ip}', ip); const r = await this.httpClient.get(url); return r.data ? api.parse(r.data) : null; } catch { return null; } }
  private checkSuspiciousRanges(ip: string): string | null { const parts = ip.split('.').map(Number); if (parts.length !== 4) return null; for (const range of this.suspiciousRanges) { const rp = range.range.split('.').map(Number); let match = true; for (let i = 0; i < Math.floor(range.mask / 8); i++) { if (parts[i] !== rp[i]) { match = false; break; } } if (match) return range.reason; } return null; }
  private createSuspiciousResult(ip: string, reason: string): IpCheckResult { return { ip, is_vpn: true, is_proxy: false, is_hosting: true, is_tor: false, is_datacenter: true, country: 'Unknown', city: 'Unknown', isp: reason, organization: reason, risk_score: 90, threat_level: 'high', checked_at: new Date().toISOString(), cached: false }; }
  private createLocalResult(ip: string): IpCheckResult { return { ip, is_vpn: false, is_proxy: false, is_hosting: false, is_tor: false, is_datacenter: false, country: 'Local', city: 'Local', isp: 'Local', organization: 'Local', risk_score: 0, threat_level: 'low', checked_at: new Date().toISOString(), cached: false }; }
  private createCleanResult(ip: string, c: string, ct: string, i: string, o: string): IpCheckResult { return { ip, is_vpn: false, is_proxy: false, is_hosting: false, is_tor: false, is_datacenter: false, country: c, city: ct, isp: i, organization: o, risk_score: 0, threat_level: 'low', checked_at: new Date().toISOString(), cached: false }; }
  getStats(): { cache_size: number; last_check: string } { return { cache_size: Object.keys(this.cache.getAll()).length, last_check: new Date(this.lastCheckTime).toISOString() }; }
}