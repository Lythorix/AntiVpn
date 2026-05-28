import * as fs from 'fs';
import * as path from 'path';

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  CRITICAL = 4
}

export class Logger {
  private static instance: Logger;
  private logPath: string;
  private level: LogLevel;
  private stream: fs.WriteStream;

  private constructor() {
    this.logPath = path.join(process.cwd(), 'logs', 'bot.log');
    this.level = LogLevel.INFO;
    
    // Создаем директорию если нет
    const dir = path.dirname(this.logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.stream = fs.createWriteStream(this.logPath, { flags: 'a' });
  }

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  private formatMessage(level: string, message: string, data?: any): string {
    const timestamp = new Date().toISOString();
    const base = `[${timestamp}] [${level}] ${message}`;
    
    if (data) {
      try {
        return `${base} | ${JSON.stringify(data)}`;
      } catch {
        return `${base} | [Unserializable data]`;
      }
    }
    
    return base;
  }

  private write(level: LogLevel, levelStr: string, message: string, data?: any): void {
    if (level < this.level) return;

    const formatted = this.formatMessage(levelStr, message, data);
    
    // Консоль с цветом
    const colors: Record<string, string> = {
      'DEBUG': '\x1b[36m',
      'INFO': '\x1b[32m',
      'WARN': '\x1b[33m',
      'ERROR': '\x1b[31m',
      'CRITICAL': '\x1b[35m'
    };

    console.log(`${colors[levelStr] || ''}${formatted}\x1b[0m`);
    
    // Файл
    this.stream.write(formatted + '\n');
  }

  debug(message: string, data?: any): void {
    this.write(LogLevel.DEBUG, 'DEBUG', message, data);
  }

  info(message: string, data?: any): void {
    this.write(LogLevel.INFO, 'INFO', message, data);
  }

  warn(message: string, data?: any): void {
    this.write(LogLevel.WARN, 'WARN', message, data);
  }

  error(message: string, data?: any): void {
    this.write(LogLevel.ERROR, 'ERROR', message, data);
  }

  critical(message: string, data?: any): void {
    this.write(LogLevel.CRITICAL, 'CRITICAL', message, data);
  }

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  close(): void {
    this.stream.end();
  }
}