import * as fs from 'fs';
import * as path from 'path';
import { AppConfig } from '../types';

export class ConfigManager {
  private static instance: ConfigManager;
  private config!: AppConfig;

  private constructor() {}

  static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  load(): AppConfig {
    const configPath = path.join(process.cwd(), 'config.json');
    
    if (!fs.existsSync(configPath)) {
      throw new Error(`❌ Config file not found: ${configPath}`);
    }

    const raw = fs.readFileSync(configPath, 'utf-8');
    this.config = JSON.parse(raw) as AppConfig;
    
    // Валидация
    this.validate();
    
    return this.config;
  }

  private validate(): void {
    const required = [
      'server.host',
      'server.port',
      'server.rcon_password',
      'discord.webhook_url',
      'monitoring.status_interval_seconds'
    ];

    for (const key of required) {
      const value = key.split('.').reduce((obj, k) => obj?.[k], this.config as any);
      if (!value && value !== 0) {
        throw new Error(`❌ Missing required config: ${key}`);
      }
    }

    console.log('✅ Config validated successfully');
  }

  get<K extends keyof AppConfig>(key: K): AppConfig[K] {
    return this.config[key];
  }

  getAll(): AppConfig {
    return { ...this.config };
  }
}