import { Waf } from './core/Waf.js';
import type { WafConfig, WafMiddleware, Plugin } from './types/index.js';

export function waf(config?: Partial<WafConfig>): WafMiddleware {
  return new Waf(config).middleware();
}

export function createWaf(config?: Partial<WafConfig>): Waf {
  return new Waf(config);
}

export { Waf } from './core/Waf.js';
export { DynamicBanList, ipFilterMiddleware } from './firewall/IpFilter.js';
export { RateLimiter } from './rateLimit/RateLimiter.js';
export { MemoryStore } from './rateLimit/MemoryStore.js';
export { RedisStore } from './rateLimit/RedisStore.js';
export { securityHeaders } from './security/headers.js';
export { analyzeBotSignals } from './botDetection/heuristics.js';
export { ChallengeManager } from './botDetection/Challenge.js';
export { stripPollutedKeys } from './detectors/noSqlAndPrototype.js';
export { defaultConfig } from './core/defaults.js';
export type { WafConfig, WafMiddleware, Plugin, ThreatEvent, Detector, DetectorResult, RateLimitRule } from './types/index.js';
