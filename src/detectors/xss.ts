import type { Detector, DetectorResult, ScanInput } from '../types/index.js';

const patterns: Array<{ rule: string; score: number; test: RegExp }> = [
  { rule: 'script-tag', score: 90, test: /<script[\s\S]*?>|<\/script>/i },
  { rule: 'event-handler', score: 75, test: /\bon(error|load|click|mouseover|focus|input|animationstart)\s*=/i },
  { rule: 'javascript-uri', score: 70, test: /javascript\s*:/i },
  { rule: 'svg-vector', score: 65, test: /<svg[\s\S]*?on\w+\s*=/i },
  { rule: 'iframe-injection', score: 60, test: /<iframe[\s\S]*?>/i },
  { rule: 'html-entity-evasion', score: 55, test: /&#x?[0-9a-f]+;.*(script|onerror|onload)/i },
  { rule: 'dom-sink', score: 60, test: /\b(document\.write|innerHTML\s*=|eval\s*\()/i },
  { rule: 'css-expression', score: 50, test: /expression\s*\(|url\s*\(\s*javascript:/i },
  { rule: 'template-literal-injection', score: 55, test: /\$\{[\s\S]*?(document|window)[\s\S]*?\}/i }
];

function decodeEntities(raw: string): string {
  return raw
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)));
}

export const xssDetector: Detector = {
  name: 'xss',
  scan(input: ScanInput): DetectorResult[] {
    const candidates = [input.raw, decodeEntities(input.raw)];
    const results: DetectorResult[] = [];
    for (const value of candidates) {
      for (const p of patterns) {
        if (p.test.test(value)) {
          results.push({
            matched: true,
            category: 'xss',
            rule: p.rule,
            score: p.score,
            meta: { field: input.key, source: input.source }
          });
        }
      }
    }
    return dedupe(results);
  }
};

function dedupe(results: DetectorResult[]): DetectorResult[] {
  const seen = new Set<string>();
  return results.filter((r) => {
    const key = `${r.rule}:${r.meta?.field}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
