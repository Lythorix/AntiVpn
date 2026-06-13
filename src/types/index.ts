// IP check result from various detection methods
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

// Cached IP data with timestamp for TTL validation
export interface CachedIpData {
  result: IpCheckResult;
  timestamp: number;
}

// Player tracking information
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

// Player status flags
export interface PlayerFlags {
  is_whitelisted: boolean;
  is_blacklisted: boolean;
  is_vpn: boolean;
  is_proxy: boolean;
  is_suspicious: boolean;
  is_trusted: boolean;
}

// Player info from server status
export interface StatusPlayer {
  id: number;
  score: number;
  latency: number;
  nickname: string;
  clan: string;
  ip: string;
}

// Server status response
export interface StatusResponse {
  players: StatusPlayer[];
  raw: string;
  timestamp: string;
}

// Alert payload for Discord webhooks
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

// Whitelist entry
export interface WhitelistEntry {
  ip: string;
  reason: string;
  added_at: string;
}

// Whitelist data structure
export interface WhitelistData {
  ips: string[];
  players: string[];
  providers: string[];
  auto_added: WhitelistEntry[];
}

// Blacklist entry
export interface BlacklistEntry {
  ip: string;
  player?: string;
  reason: string;
  added_at: string;
  detection_method: string;
}

// Blacklist data structure
export interface BlacklistData {
  ips: string[];
  players: string[];
  auto_added: BlacklistEntry[];
}

// Application configuration
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
    hourly_reconnect: boolean;
    reconnect_interval_minutes: number;
  };
  logs: {
    cleanup_interval_hours: number;
    max_age_days: number;
    keep_only_today: boolean;
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

// Queue task for processing
export interface QueueTask {
  id: string;
  type: 'ip_check' | 'webhook_alert' | 'rcon_command';
  data: any;
  priority: number;
  added_at: number;
  retries: number;
  max_retries: number;
}

// RCON authentication status
export interface RconAuthStatus {
  AuthLevel: number;
  ReceiveCommands: number;
}
