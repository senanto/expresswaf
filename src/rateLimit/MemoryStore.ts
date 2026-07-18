import type { Store } from '../types/index.js';

interface Bucket {
  count: number;
  resetAt: number;
}

export class MemoryStore implements Store {
  private buckets = new Map<string, Bucket>();

  async incr(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const existing = this.buckets.get(key);
    if (!existing || existing.resetAt <= now) {
      this.buckets.set(key, { count: 1, resetAt: now + windowMs });
      return 1;
    }
    existing.count += 1;
    return existing.count;
  }

  async get(key: string): Promise<number> {
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= Date.now()) return 0;
    return bucket.count;
  }

  async reset(key: string): Promise<void> {
    this.buckets.delete(key);
  }

  sweep(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) this.buckets.delete(key);
    }
  }
}
