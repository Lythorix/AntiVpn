// src/services/RconService.ts - ORIGINAL
import { StatusResponse, StatusPlayer, RconAuthStatus } from '../types';
import { Logger } from '../utils/Logger';

// RCON service - handles server communication - singleton pattern
export class RconService {
  private client: any;
  private logger: Logger;
  private rconLines: string[] = [];
  private isAuthenticated: boolean = false;
  private authPromise: Promise<void> | null = null;
  private authResolve: (() => void) | null = null;
  private onPlayerJoinCallback: ((player: StatusPlayer) => void) | null = null;
  private onPlayerLeaveCallback: ((clientId: number) => void) | null = null;
  private pendingJoins: Map<number, string> = new Map();
  private commandQueue: Promise<unknown> = Promise.resolve();

  constructor(client: any) {
    this.client = client;
    this.logger = Logger.getInstance();
    this.setupRconListener();
  }

  private setupRconListener(): void {
    this.client.rcon.on('rcon_line', (line: string) => {
      this.rconLines.push(line);

      const enterMatch = line.match(/player has entered the game\. ClientId=(\d+) addr=([^\s]+)/);
      if (enterMatch) {
        const clientId = parseInt(enterMatch[1]);
        const ip = enterMatch[2].split(':')[0];

        this.logger.info(`Player joined: ID=${clientId}, IP=${ip}`);
        this.pendingJoins.set(clientId, ip);
        this.tryGetPlayerInfo(clientId, ip, 0);
      }

      const leaveMatch = line.match(/player has left the game\. ClientId=(\d+)/);
      if (leaveMatch) {
        const clientId = parseInt(leaveMatch[1]);
        this.logger.info(`Player left: ID=${clientId}`);

        if (this.onPlayerLeaveCallback) {
          this.onPlayerLeaveCallback(clientId);
        }

        this.pendingJoins.delete(clientId);
      }

      const chatEnterMatch = line.match(/I chat: \*\*\* '(.+?)' entered and joined the game/);
      if (chatEnterMatch && this.pendingJoins.size === 1) {
        const nickname = chatEnterMatch[1];
        const [cid, ip] = this.pendingJoins.entries().next().value as [number, string];

        this.logger.info(`Chat join: ${nickname}`);
        this.pendingJoins.delete(cid);

        if (this.onPlayerJoinCallback) {
          this.onPlayerJoinCallback({
            id: cid,
            nickname,
            clan: '',
            ip,
            score: 0,
            latency: 0
          });
        }
      }
    });

    this.client.rcon.on('rcon_auth_status', (status: RconAuthStatus) => {
      this.isAuthenticated = true;
      this.logger.info(`RCON authenticated - Level: ${status.AuthLevel}`);
      if (this.authResolve) {
        this.authResolve();
        this.authResolve = null;
      }
    });
  }

  private async tryGetPlayerInfo(clientId: number, ip: string, attempt: number): Promise<void> {
    if (!this.pendingJoins.has(clientId)) return;

    if (attempt >= 5) {
      this.logger.warn(`Failed to get name for ID=${clientId}`);
      this.pendingJoins.delete(clientId);

      if (this.onPlayerJoinCallback) {
        this.onPlayerJoinCallback({
          id: clientId,
          nickname: 'Unknown',
          clan: '',
          ip,
          score: 0,
          latency: 0
        });
      }
      return;
    }

    const delay = 2000 + (attempt * 2000);
    await this.delay(delay);

    try {
      const status = await this.executeStatus();
      const player = status.players.find(p => p.id === clientId);

      if (player && player.nickname && player.nickname !== 'Unknown') {
        this.logger.info(`Got name: ${player.nickname} (ID=${clientId})`);
        this.pendingJoins.delete(clientId);
        if (this.onPlayerJoinCallback) {
          this.onPlayerJoinCallback(player);
        }
      } else if (!player && attempt >= 1) {
        this.logger.info(`Player ID=${clientId} already left, checking IP=${ip}`);
        this.pendingJoins.delete(clientId);
        if (this.onPlayerJoinCallback) {
          this.onPlayerJoinCallback({
            id: clientId,
            nickname: 'Unknown',
            clan: '',
            ip,
            score: 0,
            latency: 0
          });
        }
      } else {
        this.logger.debug(`Retry ${attempt + 1}/5 for ID=${clientId}`);
        await this.tryGetPlayerInfo(clientId, ip, attempt + 1);
      }
    } catch (error) {
      await this.tryGetPlayerInfo(clientId, ip, attempt + 1);
    }
  }

  onPlayerJoin(callback: (player: StatusPlayer) => void): void {
    this.onPlayerJoinCallback = callback;
  }

  onPlayerLeave(callback: (clientId: number) => void): void {
    this.onPlayerLeaveCallback = callback;
  }

  async login(password: string, username?: string): Promise<void> {
    this.authPromise = new Promise<void>((resolve) => {
      this.authResolve = resolve;
    });

    try {
      if (username) {
        this.client.rcon.auth(username, password);
      } else {
        this.client.rcon.auth(password);
      }

      const timeout = setTimeout(() => {
        if (this.authResolve) {
          this.authResolve();
          this.authResolve = null;
        }
      }, 10000);

      await this.authPromise;
      clearTimeout(timeout);

      if (!this.isAuthenticated) throw new Error('RCON authentication failed');
    } catch (error) {
      this.logger.error('RCON login error', error);
      throw error;
    }
  }

  async execute(command: string): Promise<string[]> {
    const run = (): Promise<string[]> => {
      this.rconLines = [];
      return new Promise((resolve) => {
        const timeout = setTimeout(() => resolve([...this.rconLines]), 3000);
        try {
          this.client.rcon.rcon(command);
          setTimeout(() => {
            clearTimeout(timeout);
            resolve([...this.rconLines]);
          }, command === 'status' ? 2000 : 1000);
        } catch (error) {
          clearTimeout(timeout);
          resolve([]);
        }
      });
    };

    const result = this.commandQueue.then(run, run);
    this.commandQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async executeStatus(): Promise<StatusResponse> {
    const lines = await this.execute('status');
    const players = this.parseStatusOutput(lines);
    return { players, raw: lines.join('\n'), timestamp: new Date().toISOString() };
  }

  private parseStatusOutput(lines: string[]): StatusPlayer[] {
    const players: StatusPlayer[] = [];

    for (const line of lines) {
      if (!line.trim() ||
          line.includes('rcon=') ||
          line.includes('player has entered') ||
          line.includes('player has left') ||
          line.includes('I chat:') ||
          line.includes('I game:') ||
          line.includes('I ddnet:')) {
        continue;
      }

      const fields = this.parseStatusFields(line);
      const id = fields.get('id');
      const addr = fields.get('addr');
      const name = fields.get('name');

      if (id && addr && name) {
        players.push({
          id: parseInt(id),
          score: parseInt(fields.get('score') || '0') || 0,
          latency: parseInt(fields.get('latency') || '0') || 0,
          nickname: name,
          clan: fields.get('clan') || '',
          ip: addr.split(':')[0]
        });
      }
    }

    return players.filter((p, i, self) => self.findIndex(t => t.id === p.id) === i);
  }

  private parseStatusFields(line: string): Map<string, string> {
    const fields = new Map<string, string>();
    const regex = /(\w+)=('(?:\\'|[^'])*'|[^\s]+)/g;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(line)) !== null) {
      const rawValue = match[2];
      const value = rawValue.startsWith("'") && rawValue.endsWith("'")
        ? rawValue.slice(1, -1).replace(/\\'/g, "'")
        : rawValue;
      fields.set(match[1], value);
    }

    return fields;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}