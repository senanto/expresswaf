import type { Store } from '../types/index.js';

type RedisLike = {
  multi(): { incr(key: string): unknown; pexpire(key: string, ms: number): unknown; exec(): Promise<unknown> };
  get(key: string): Promise<string | null>;
  del(key: string): Promise<number>;
};

export class RedisStore implements Store {
  private client: RedisLike;

  private constructor(client: RedisLike) {
    this.client = client;
  }

  static async connect(url: string): Promise<RedisStore> {
    const { default: IORedis } = await import('ioredis');
    const client = new IORedis(url) as unknown as RedisLike;
    return new RedisStore(client);
  }

  async incr(key: string, windowMs: number): Promise<number> {
    const tx = this.client.multi();
    tx.incr(key);
    tx.pexpire(key, windowMs);
    const result = await tx.exec();
    const first = Array.isArray(result) ? result[0] : null;
    const count = Array.isArray(first) ? Number(first[1]) : 1;
    return Number.isFinite(count) ? count : 1;
  }

  async get(key: string): Promise<number> {
    const value = await this.client.get(key);
    return value ? Number(value) : 0;
  }

  async reset(key: string): Promise<void> {
    await this.client.del(key);
  }
}
