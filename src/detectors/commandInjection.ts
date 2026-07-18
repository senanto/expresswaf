import type { Detector, DetectorResult, ScanInput } from '../types/index.js';

const patterns: Array<{ rule: string; score: number; test: RegExp }> = [
  { rule: 'shell-metachar-chain', score: 85, test: /[;&|`]\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh|powershell)\b/i },
  { rule: 'command-substitution', score: 80, test: /\$\([^)]+\)|`[^`]+`/ },
  { rule: 'path-binary', score: 60, test: /\b(\/bin\/(ba)?sh|\/etc\/passwd|cmd\.exe|powershell\.exe)\b/i },
  { rule: 'redirection-chain', score: 55, test: />\s*\/dev\/(null|tcp)/i },
  { rule: 'pipe-to-shell', score: 75, test: /\|\s*(sh|bash|nc|ncat)\b/i }
];

export const commandInjectionDetector: Detector = {
  name: 'command-injection',
  scan(input: ScanInput): DetectorResult[] {
    const results: DetectorResult[] = [];
    for (const p of patterns) {
      if (p.test.test(input.raw)) {
        results.push({ matched: true, category: 'command-injection', rule: p.rule, score: p.score, meta: { field: input.key } });
      }
    }
    return results;
  }
};
