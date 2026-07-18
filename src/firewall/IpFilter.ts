import type { Request, Response, NextFunction } from 'express';
import type { WafConfig } from '../types/index.js';
import { ipMatchesCidr } from './cidr.js';

function matchesAny(ip: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern === ip) return true;
    if (pattern.includes('/') && ipMatchesCidr(ip, pattern)) return true;
  }
  return false;
}

export function ipFilterMiddleware(config: WafConfig['ipFilter']) {
  return function ipFilter(req: Request, res: Response, next: NextFunction): void {
    const ip = req.ip ?? req.socket.remoteAddress ?? '';
    if (config.whitelist.length > 0 && matchesAny(ip, config.whitelist)) {
      next();
      return;
    }
    if (matchesAny(ip, config.blacklist)) {
      res.status(403).json({ error: 'ip_blocked' });
      return;
    }
    next();
  };
}

export class DynamicBanList {
  private bans = new Map<string, number>();

  ban(ip: string, durationMs: number): void {
    this.bans.set(ip, Date.now() + durationMs);
  }

  banPermanent(ip: string): void {
    this.bans.set(ip, Infinity);
  }

  isBanned(ip: string): boolean {
    const expiry = this.bans.get(ip);
    if (expiry === undefined) return false;
    if (expiry < Date.now()) {
      this.bans.delete(ip);
      return false;
    }
    return true;
  }

  unban(ip: string): void {
    this.bans.delete(ip);
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      const ip = req.ip ?? req.socket.remoteAddress ?? '';
      if (this.isBanned(ip)) {
        res.status(403).json({ error: 'ip_banned' });
        return;
      }
      next();
    };
  }
}
