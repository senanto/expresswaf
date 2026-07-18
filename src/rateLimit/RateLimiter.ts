import type { Request, Response, NextFunction } from 'express';
import type { RateLimitRule, Store } from '../types/index.js';

interface TokenBucketState {
  tokens: number;
  lastRefill: number;
}

export class RateLimiter {
  private buckets = new Map<string, TokenBucketState>();

  constructor(private store: Store) {}

  middleware(rule: RateLimitRule) {
    const algorithm = rule.algorithm ?? 'sliding-window';
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      if (rule.match && !rule.match(req)) return next();
      const key = (rule.keyGenerator ?? defaultKeyGenerator)(req);
      const allowed =
        algorithm === 'token-bucket'
          ? this.tokenBucketCheck(key, rule)
          : await this.counterCheck(key, rule);
      if (!allowed) {
        res.setHeader('Retry-After', Math.ceil(rule.windowMs / 1000).toString());
        res.status(429).json({ error: 'rate_limit_exceeded', retryAfterMs: rule.windowMs });
        return;
      }
      next();
    };
  }

  private async counterCheck(key: string, rule: RateLimitRule): Promise<boolean> {
    const count = await this.store.incr(key, rule.windowMs);
    return count <= rule.max;
  }

  private tokenBucketCheck(key: string, rule: RateLimitRule): boolean {
    const now = Date.now();
    const refillRate = rule.max / rule.windowMs;
    const state = this.buckets.get(key) ?? { tokens: rule.max, lastRefill: now };
    const elapsed = now - state.lastRefill;
    state.tokens = Math.min(rule.max, state.tokens + elapsed * refillRate);
    state.lastRefill = now;
    if (state.tokens < 1) {
      this.buckets.set(key, state);
      return false;
    }
    state.tokens -= 1;
    this.buckets.set(key, state);
    return true;
  }
}

function defaultKeyGenerator(req: Request): string {
  return `${req.ip}:${req.method}:${req.baseUrl}${req.path}`;
}
