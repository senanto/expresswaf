import pino from 'pino';
import type { Logger, WafConfig } from '../types/index.js';

export function createLogger(config: WafConfig['logging']): Logger {
  const instance = pino({
    level: config.level === 'silent' ? 'silent' : config.level,
    formatters: { level: (label) => ({ level: label }) },
    timestamp: pino.stdTimeFunctions.isoTime
  });
  return {
    info: (obj, msg) => instance.info(obj, msg),
    warn: (obj, msg) => instance.warn(obj, msg),
    error: (obj, msg) => instance.error(obj, msg),
    debug: (obj, msg) => instance.debug(obj, msg)
  };
}
