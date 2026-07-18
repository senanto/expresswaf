import type { Detector, DetectorResult, ScanInput } from '../types/index.js';

const noSqlOperators = ['$where', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$regex', '$or', '$and', '$exists', '$function'];

export const noSqlInjectionDetector: Detector = {
  name: 'nosql-injection',
  scan(input: ScanInput): DetectorResult[] {
    const results: DetectorResult[] = [];
    for (const op of noSqlOperators) {
      if (input.raw.includes(op)) {
        results.push({
          matched: true,
          category: 'nosql-injection',
          rule: `operator:${op}`,
          score: op === '$where' || op === '$function' ? 85 : 60,
          meta: { field: input.key }
        });
      }
    }
    return results;
  }
};

const dangerousKeys = ['__proto__', 'constructor', 'prototype'];

export const prototypePollutionDetector: Detector = {
  name: 'prototype-pollution',
  scan(input: ScanInput): DetectorResult[] {
    const results: DetectorResult[] = [];
    for (const key of dangerousKeys) {
      if (input.key === key || input.raw.includes(`"${key}"`)) {
        results.push({
          matched: true,
          category: 'prototype-pollution',
          rule: `key:${key}`,
          score: 90,
          meta: { field: input.key }
        });
      }
    }
    return results;
  }
};

export function stripPollutedKeys<T extends Record<string, unknown>>(obj: T): T {
  for (const key of dangerousKeys) delete (obj as Record<string, unknown>)[key];
  return obj;
}
