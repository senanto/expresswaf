import type { Request } from 'express';
import type { Detector, DetectorResult, ScanInput } from '../types/index.js';

const crlfPatterns: Array<{ rule: string; score: number; test: RegExp }> = [
  { rule: 'raw-crlf', score: 85, test: /\r\n|\n\r/ },
  { rule: 'encoded-crlf', score: 80, test: /%0d%0a|%0a%0d/i },
  { rule: 'header-smuggling', score: 78, test: /(set-cookie|content-length|transfer-encoding)\s*:/i }
];

export const crlfDetector: Detector = {
  name: 'crlf-injection',
  scan(input: ScanInput): DetectorResult[] {
    const results: DetectorResult[] = [];
    for (const p of crlfPatterns) {
      if (p.test.test(input.raw)) {
        results.push({ matched: true, category: 'crlf-injection', rule: p.rule, score: p.score, meta: { field: input.key } });
      }
    }
    return results;
  }
};

export function detectHpp(req: Request): DetectorResult[] {
  const results: DetectorResult[] = [];
  for (const [key, value] of Object.entries(req.query)) {
    if (Array.isArray(value) && value.length > 1) {
      results.push({ matched: true, category: 'hpp', rule: 'duplicate-query-param', score: 45, meta: { field: key, count: value.length } });
    }
  }
  return results;
}
