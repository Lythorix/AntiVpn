export interface IpCheckResult {
  ip: string;
  is_vpn: boolean;
  is_proxy: boolean;
  is_hosting: boolean;
  is_tor: boolean;
  is_datacenter: boolean;
  country?: string;
  city?: string;
  isp?: string;
  organization?: string;
  risk_score?: number;
  threat_level?: 'low' | 'medium' | 'high' | 'critical';
  checked_at: string;
  cached?: boolean;
}

export interface CachedIpData {
  result: IpCheckResult;
  timestamp: number;
}

export interface TrackedPlayer {
  id: number;
  nickname: string;
  clan: string;
  ip: string;
  first_seen: string;
  last_seen: string;
  sessions: number;
  flags: PlayerFlags;
  ip_check?: IpCheckResult;
}

export interface PlayerFlags {
  is_whitelisted: boolean;
  is_blacklisted: boolean;
  is_vpn: boolean;
  is_proxy: boolean;
  is_suspicious: boolean;
  is_trusted: boolean;
}

export interface StatusPlayer {
  id: number;
  score: number;
  latency: number;
  nickname: string;
  clan: string;
  ip: string;
}

export interface StatusResponse {
  players: StatusPlayer[];
  raw: string;
  timestamp: string;
}

export interface AlertPayload {
  type: 'vpn_detected' | 'proxy_detected' | 'tor_detected' | 'hosting_detected' | 'blacklist_add' | 'error' | 'info' | 'reconnect' | 'startup';
  player?: {
    nickname: string;
    ip: string;
    id: number;
  };
  details?: Record<string, any>;
  timestamp: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface WhitelistEntry {
  ip: string;
  reason: string;
  added_at: string;
}

export interface WhitelistData {
  ips: string[];
  players: string[];
  auto_added: WhitelistEntry[];
}

export interface BlacklistEntry {
  ip: string;
  player?: string;
  reason: string;
  added_at: string;
  detection_method: string;
}

export interface BlacklistData {
  ips: string[];
  players: string[];
  auto_added: BlacklistEntry[];
}

export interface AppConfig {
  server: {
    host: string;
    port: number;
    rcon_password: string;
    rcon_username?: string;
  };
  discord: {
    webhook_url: string;
    alert_webhook_url: string;
  };
  ipcheck: {
    rate_limit_ms: number;
    cache_ttl_hours: number;
    retry_attempts: number;
    retry_delay_ms: number;
  };
  monitoring: {
    status_interval_seconds: number;
    reconnect_delay_ms: number;
    max_reconnect_attempts: number;
  };
  bot: {
    nickname: string;
    clan: string;
  };
  auto_ban: {
    enabled: boolean;
    mode: 'warn' | 'autoban';
    ban_duration_minutes: number;
  };
}

export interface QueueTask {
  id: string;
  type: 'ip_check' | 'webhook_alert' | 'rcon_command';
  data: any;
  priority: number;
  added_at: number;
  retries: number;
  max_retries: number;
}

export interface RconAuthStatus {
  AuthLevel: number;
  ReceiveCommands: number;
}