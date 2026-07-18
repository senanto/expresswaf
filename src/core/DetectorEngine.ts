import type { Request } from 'express';
import type { Detector, DetectorResult, ScanInput, WafConfig } from '../types/index.js';
import { sqlInjectionDetector } from '../detectors/sqlInjection.js';
import { xssDetector } from '../detectors/xss.js';
import { commandInjectionDetector } from '../detectors/commandInjection.js';
import { noSqlInjectionDetector, prototypePollutionDetector } from '../detectors/noSqlAndPrototype.js';
import { pathTraversalDetector } from '../detectors/pathTraversal.js';
import { makeSsrfDetector } from '../detectors/ssrf.js';
import { crlfDetector, detectHpp } from '../detectors/crlfAndHpp.js';

export class DetectorEngine {
  private detectors: Detector[] = [];

  constructor(config: WafConfig) {
    if (config.detectors.sqlInjection) this.detectors.push(sqlInjectionDetector);
    if (config.detectors.xss) this.detectors.push(xssDetector);
    if (config.detectors.commandInjection) this.detectors.push(commandInjectionDetector);
    if (config.detectors.noSqlInjection) this.detectors.push(noSqlInjectionDetector);
    if (config.detectors.prototypePollution) this.detectors.push(prototypePollutionDetector);
    if (config.detectors.pathTraversal) this.detectors.push(pathTraversalDetector);
    if (config.detectors.ssrf) this.detectors.push(makeSsrfDetector(config.ssrf));
    if (config.detectors.crlf) this.detectors.push(crlfDetector);
  }

  register(detector: Detector): void {
    this.detectors.push(detector);
  }

  scanRequest(req: Request, config: WafConfig): DetectorResult[] {
    const results: DetectorResult[] = [];
    for (const [source, bag] of entries(req)) {
      for (const [key, value] of flatten(bag)) {
        const input: ScanInput = { req, raw: String(value), source, key };
        for (const detector of this.detectors) {
          results.push(...detector.scan(input));
        }
      }
    }
    if (config.detectors.hpp) results.push(...detectHpp(req));
    return results;
  }
}

function entries(req: Request): Array<[ScanInput['source'], Record<string, unknown>]> {
  return [
    ['query', req.query as Record<string, unknown>],
    ['body', (req.body ?? {}) as Record<string, unknown>],
    ['params', req.params as Record<string, unknown>],
    ['headers', req.headers as Record<string, unknown>],
    ['cookies', (req as unknown as { cookies?: Record<string, unknown> }).cookies ?? {}]
  ];
}

function flatten(obj: Record<string, unknown>, prefix = ''): Array<[string, unknown]> {
  const out: Array<[string, unknown]> = [];
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      out.push(...flatten(value as Record<string, unknown>, fullKey));
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => out.push([`${fullKey}[${i}]`, v]));
    } else {
      out.push([fullKey, value]);
    }
  }
  return out;
}
