import type { Request, Response, NextFunction } from 'express';

export type Verdict = 'allow' | 'block' | 'challenge' | 'log';

export interface ThreatEvent {
  id: string;
  timestamp: number;
  ip: string;
  method: string;
  path: string;
  category: string;
  rule: string;
  riskScore: number;
  verdict: Verdict;
  meta?: Record<string, unknown>;
}

export interface DetectorResult {
  matched: boolean;
  category: string;
  rule: string;
  score: number;
  meta?: Record<string, unknown>;
}

export interface Detector {
  name: string;
  scan(input: ScanInput): DetectorResult[];
}

export interface ScanInput {
  req: Request;
  raw: string;
  source: 'query' | 'body' | 'headers' | 'params' | 'cookies';
  key: string;
}

export interface Store {
  incr(key: string, windowMs: number): Promise<number>;
  get(key: string): Promise<number>;
  reset(key: string): Promise<void>;
}

export interface Plugin {
  name: string;
  onInit?(ctx: PluginContext): void;
  onRequest?(req: Request, res: Response, ctx: PluginContext): Verdict | void;
  onThreat?(event: ThreatEvent, ctx: PluginContext): void;
}

export interface PluginContext {
  config: WafConfig;
  logger: Logger;
  emit(event: string, payload: unknown): void;
}

export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
  debug(obj: Record<string, unknown>, msg?: string): void;
}

export interface RateLimitRule {
  windowMs: number;
  max: number;
  algorithm?: 'sliding-window' | 'token-bucket' | 'fixed-window';
  keyGenerator?: (req: Request) => string;
  match?: (req: Request) => boolean;
}

export interface WafConfig {
  mode: 'block' | 'monitor';
  riskThresholdBlock: number;
  riskThresholdChallenge: number;
  bodyLimitBytes: number;
  trustProxy: boolean;
  detectors: {
    sqlInjection: boolean;
    xss: boolean;
    commandInjection: boolean;
    noSqlInjection: boolean;
    pathTraversal: boolean;
    ssrf: boolean;
    prototypePollution: boolean;
    crlf: boolean;
    hpp: boolean;
  };
  headers: {
    hsts: boolean;
    csp: string | false;
    xFrameOptions: 'DENY' | 'SAMEORIGIN' | false;
    xContentTypeOptions: boolean;
    referrerPolicy: string | false;
  };
  rateLimit: {
    enabled: boolean;
    global: RateLimitRule;
    routes: RateLimitRule[];
    store: 'memory' | 'redis';
    redisUrl?: string;
  };
  ipFilter: {
    whitelist: string[];
    blacklist: string[];
    blockedCountries: string[];
  };
  botDetection: {
    enabled: boolean;
    blockHeadless: boolean;
    challengeSuspicious: boolean;
  };
  ssrf: {
    blockPrivateNetworks: boolean;
    blockCloudMetadata: boolean;
    allowedHosts?: string[];
  };
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error' | 'silent';
    destination?: string;
  };
  configPath?: string;
  hotReload: boolean;
}

export type WafMiddleware = (req: Request, res: Response, next: NextFunction) => void;
