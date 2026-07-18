import type { WafConfig } from '../types/index.js';

export function defaultConfig(): WafConfig {
  return {
    mode: 'block',
    riskThresholdBlock: 70,
    riskThresholdChallenge: 40,
    bodyLimitBytes: 1024 * 1024,
    trustProxy: true,
    detectors: {
      sqlInjection: true,
      xss: true,
      commandInjection: true,
      noSqlInjection: true,
      pathTraversal: true,
      ssrf: true,
      prototypePollution: true,
      crlf: true,
      hpp: true
    },
    headers: {
      hsts: true,
      csp: "default-src 'self'",
      xFrameOptions: 'DENY',
      xContentTypeOptions: true,
      referrerPolicy: 'no-referrer'
    },
    rateLimit: {
      enabled: true,
      global: { windowMs: 60_000, max: 300, algorithm: 'sliding-window' },
      routes: [],
      store: 'memory'
    },
    ipFilter: {
      whitelist: [],
      blacklist: [],
      blockedCountries: []
    },
    botDetection: {
      enabled: true,
      blockHeadless: true,
      challengeSuspicious: true
    },
    ssrf: {
      blockPrivateNetworks: true,
      blockCloudMetadata: true
    },
    logging: {
      level: 'info'
    },
    hotReload: false
  };
}

export function mergeConfig(base: WafConfig, patch: Partial<WafConfig>): WafConfig {
  return {
    ...base,
    ...patch,
    detectors: { ...base.detectors, ...patch.detectors },
    headers: { ...base.headers, ...patch.headers },
    rateLimit: { ...base.rateLimit, ...patch.rateLimit },
    ipFilter: { ...base.ipFilter, ...patch.ipFilter },
    botDetection: { ...base.botDetection, ...patch.botDetection },
    ssrf: { ...base.ssrf, ...patch.ssrf },
    logging: { ...base.logging, ...patch.logging }
  };
}
