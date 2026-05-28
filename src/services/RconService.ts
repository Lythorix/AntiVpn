// src/services/RconService.ts
import { StatusResponse, StatusPlayer, RconAuthStatus } from '../types';
import { Logger } from '../utils/Logger';

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

  constructor(client: any) {
    this.client = client;
    this.logger = Logger.getInstance();
    this.setupRconListener();
  }

  private setupRconListener(): void {
    this.client.rcon.on('rcon_line', (line: string) => {
      this.rconLines.push(line);
      
      // Вход игрока: player has entered the game. ClientId=17 addr=5.227.26.231:49874
      const enterMatch = line.match(/player has entered the game\. ClientId=(\d+) addr=([^\s]+)/);
      if (enterMatch) {
        const clientId = parseInt(enterMatch[1]);
        const ip = enterMatch[2].split(':')[0];
        
        this.logger.info(`👤 Player joined: ID=${clientId}, IP=${ip}`);
        this.pendingJoins.set(clientId, ip);
        this.tryGetPlayerInfo(clientId, ip, 0);
      }
      
      // Выход игрока: player has left the game. ClientId=17
      const leaveMatch = line.match(/player has left the game\. ClientId=(\d+)/);
      if (leaveMatch) {
        const clientId = parseInt(leaveMatch[1]);
        this.logger.info(`👋 Player left: ID=${clientId}`);
        
        if (this.onPlayerLeaveCallback) {
          this.onPlayerLeaveCallback(clientId);
        }
        
        this.pendingJoins.delete(clientId);
      }
      
      // Чат вход: *** 'nickname' entered and joined the game
      const chatEnterMatch = line.match(/I chat: \*\*\* '(.+?)' entered and joined the game/);
      if (chatEnterMatch) {
        const nickname = chatEnterMatch[1];
        this.logger.info(`💬 Chat join: ${nickname}`);
        
        // Ищем pending join без ника
        for (const [cid, ip] of this.pendingJoins) {
          this.pendingJoins.delete(cid);
          if (this.onPlayerJoinCallback) {
            this.onPlayerJoinCallback({
              id: cid,
              nickname: nickname,
              clan: '',
              ip: ip,
              score: 0,
              latency: 0
            });
          }
          break;
        }
      }
    });

    this.client.rcon.on('rcon_auth_status', (status: RconAuthStatus) => {
      this.isAuthenticated = true;
      this.logger.info(`🔑 RCON authenticated - Level: ${status.AuthLevel}`);
      if (this.authResolve) { this.authResolve(); this.authResolve = null; }
    });
  }

  private async tryGetPlayerInfo(clientId: number, ip: string, attempt: number): Promise<void> {
    if (attempt >= 5) {
      this.logger.warn(`⚠️ Failed to get name for ID=${clientId}`);
      if (this.onPlayerJoinCallback && this.pendingJoins.has(clientId)) {
        this.pendingJoins.delete(clientId);
        this.onPlayerJoinCallback({
          id: clientId,
          nickname: `Player_${clientId}`,
          clan: '',
          ip: ip,
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
        this.logger.info(`✅ Got name: ${player.nickname} (ID=${clientId})`);
        this.pendingJoins.delete(clientId);
        if (this.onPlayerJoinCallback) {
          this.onPlayerJoinCallback(player);
        }
      } else if (!player && attempt >= 1) {
        this.logger.info(`⚠️ Player ID=${clientId} already left, checking IP=${ip}`);
        this.pendingJoins.delete(clientId);
        if (this.onPlayerJoinCallback) {
          this.onPlayerJoinCallback({
            id: clientId,
            nickname: `Left_Player_${clientId}`,
            clan: '',
            ip: ip,
            score: 0,
            latency: 0
          });
        }
      } else {
        this.logger.debug(`⏳ Retry ${attempt + 1}/5 for ID=${clientId}`);
        await this.tryGetPlayerInfo(clientId, ip, attempt + 1);
      }
    } catch (error) {
      this.tryGetPlayerInfo(clientId, ip, attempt + 1);
    }
  }

  onPlayerJoin(callback: (player: StatusPlayer) => void): void { 
    this.onPlayerJoinCallback = callback; 
  }

  onPlayerLeave(callback: (clientId: number) => void): void {
    this.onPlayerLeaveCallback = callback;
  }

  async login(password: string, username?: string): Promise<void> {
    this.authPromise = new Promise<void>((resolve) => { this.authResolve = resolve; });
    try {
      if (username) { this.client.rcon.auth(username, password); } 
      else { this.client.rcon.auth(password); }

      const timeout = setTimeout(() => { 
        if (this.authResolve) { this.authResolve(); this.authResolve = null; } 
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
          line.includes('I ddnet:')) continue;
          
      const idMatch = line.match(/id=(\d+)/);
      const addrMatch = line.match(/addr=([^\s]+)/);
      const nameMatch = line.match(/name='([^']*)'/);
      
      if (idMatch && addrMatch && nameMatch) {
        players.push({ 
          id: parseInt(idMatch[1]), 
          score: 0, 
          latency: 0, 
          nickname: nameMatch[1], 
          clan: '', 
          ip: addrMatch[1].split(':')[0] 
        });
      }
    }
    return players.filter((p, i, self) => self.findIndex(t => t.id === p.id) === i);
  }

  private delay(ms: number): Promise<void> { 
    return new Promise(resolve => setTimeout(resolve, ms)); 
  }
}