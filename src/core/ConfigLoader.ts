import { readFileSync, watch, FSWatcher } from 'node:fs';
import { extname } from 'node:path';
import { pathToFileURL } from 'node:url';
import yaml from 'js-yaml';
import type { WafConfig } from '../types/index.js';
import { defaultConfig, mergeConfig } from './defaults.js';

type Listener = (config: WafConfig) => void;

export class ConfigLoader {
  private current: WafConfig;
  private watcher?: FSWatcher;
  private listeners: Listener[] = [];
  private path?: string;

  constructor(seed?: Partial<WafConfig>) {
    this.current = mergeConfig(defaultConfig(), applyEnvOverrides(seed ?? {}));
  }

  get config(): WafConfig {
    return this.current;
  }

  onChange(fn: Listener): void {
    this.listeners.push(fn);
  }

  async loadFromFile(path: string, hotReload = false): Promise<WafConfig> {
    this.path = path;
    const patch = await parseFile(path);
    this.current = mergeConfig(defaultConfig(), applyEnvOverrides(patch));
    if (hotReload) this.enableHotReload(path);
    return this.current;
  }

  private enableHotReload(path: string): void {
    this.watcher?.close();
    let pending: NodeJS.Timeout | undefined;
    this.watcher = watch(path, () => {
      clearTimeout(pending);
      pending = setTimeout(async () => {
        try {
          const patch = await parseFile(path);
          this.current = mergeConfig(defaultConfig(), applyEnvOverrides(patch));
          for (const fn of this.listeners) fn(this.current);
        } catch {
          return;
        }
      }, 150);
    });
  }

  close(): void {
    this.watcher?.close();
  }
}

async function parseFile(path: string): Promise<Partial<WafConfig>> {
  const ext = extname(path).toLowerCase();
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
    const mod = await import(pathToFileURL(path).href + `?t=${Date.now()}`);
    return (mod.default ?? mod) as Partial<WafConfig>;
  }
  const raw = readFileSync(path, 'utf-8');
  if (ext === '.yaml' || ext === '.yml') {
    return (yaml.load(raw) as Partial<WafConfig>) ?? {};
  }
  return JSON.parse(raw);
}

function applyEnvOverrides(patch: Partial<WafConfig>): Partial<WafConfig> {
  const env = process.env;
  const out: Partial<WafConfig> = { ...patch };
  if (env.WAF_MODE) out.mode = env.WAF_MODE as WafConfig['mode'];
  if (env.WAF_RISK_BLOCK) out.riskThresholdBlock = Number(env.WAF_RISK_BLOCK);
  if (env.WAF_RISK_CHALLENGE) out.riskThresholdChallenge = Number(env.WAF_RISK_CHALLENGE);
  if (env.WAF_RATE_LIMIT_MAX) {
    out.rateLimit = {
      ...(patch.rateLimit ?? defaultConfig().rateLimit),
      global: {
        ...(patch.rateLimit?.global ?? defaultConfig().rateLimit.global),
        max: Number(env.WAF_RATE_LIMIT_MAX)
      }
    };
  }
  if (env.WAF_REDIS_URL) {
    out.rateLimit = { ...(out.rateLimit ?? defaultConfig().rateLimit), store: 'redis', redisUrl: env.WAF_REDIS_URL };
  }
  return out;
}
