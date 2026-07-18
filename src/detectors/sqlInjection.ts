import type { Detector, DetectorResult, ScanInput } from '../types/index.js';

const patterns: Array<{ rule: string; score: number; test: RegExp }> = [
  { rule: 'union-select', score: 90, test: /\bunion\b[\s\S]{0,40}\bselect\b/i },
  { rule: 'boolean-based', score: 70, test: /(\bor\b|\band\b)\s+['"]?\s*\d+\s*=\s*\d+/i },
  { rule: 'boolean-tautology', score: 65, test: /['"]\s*(or|and)\s*['"]?\d/i },
  { rule: 'error-based', score: 80, test: /\b(extractvalue|updatexml|convert\s*\(|exp\s*\(\s*~)/i },
  { rule: 'time-based', score: 85, test: /\b(sleep|pg_sleep|waitfor\s+delay|benchmark)\s*\(/i },
  { rule: 'stacked-queries', score: 88, test: /;\s*(drop|delete|update|insert|alter)\b/i },
  { rule: 'comment-evasion', score: 55, test: /(\/\*[\s\S]*?\*\/|--\s|#\s*$)/ },
  { rule: 'hex-encoding', score: 60, test: /0x[0-9a-f]{6,}/i },
  { rule: 'information-schema', score: 75, test: /information_schema|sysobjects|sys\.tables/i },
  { rule: 'stored-procedure', score: 70, test: /\bxp_cmdshell\b|\bsp_executesql\b/i }
];

function normalize(raw: string): string {
  let value = raw;
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(value);
      if (decoded === value) break;
      value = decoded;
    } catch {
      break;
    }
  }
  return value;
}

export const sqlInjectionDetector: Detector = {
  name: 'sql-injection',
  scan(input: ScanInput): DetectorResult[] {
    const normalized = normalize(input.raw);
    const results: DetectorResult[] = [];
    for (const p of patterns) {
      if (p.test.test(normalized)) {
        results.push({
          matched: true,
          category: 'sql-injection',
          rule: p.rule,
          score: p.score,
          meta: { field: input.key, source: input.source }
        });
      }
    }
    return results;
  }
};
