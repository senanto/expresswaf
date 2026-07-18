import type { Detector, DetectorResult, ScanInput } from '../types/index.js';

const patterns: Array<{ rule: string; score: number; test: RegExp }> = [
  { rule: 'dot-dot-slash', score: 80, test: /(\.\.\/|\.\.\\){2,}/ },
  { rule: 'encoded-traversal', score: 75, test: /%2e%2e(%2f|%5c)/i },
  { rule: 'double-encoded-traversal', score: 78, test: /%252e%252e/i },
  { rule: 'sensitive-file', score: 85, test: /\/(etc\/passwd|windows\/win\.ini|proc\/self\/environ)/i },
  { rule: 'remote-file-inclusion', score: 82, test: /^(https?|ftp):\/\/.+\.(php|txt|inc)\b/i },
  { rule: 'null-byte', score: 70, test: /%00/ }
];

export const pathTraversalDetector: Detector = {
  name: 'path-traversal',
  scan(input: ScanInput): DetectorResult[] {
    const results: DetectorResult[] = [];
    for (const p of patterns) {
      if (p.test.test(input.raw)) {
        results.push({ matched: true, category: 'path-traversal', rule: p.rule, score: p.score, meta: { field: input.key } });
      }
    }
    return results;
  }
};
