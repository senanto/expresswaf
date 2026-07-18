import type { DetectorResult, Verdict, WafConfig } from '../types/index.js';
import type { BotSignal } from '../botDetection/heuristics.js';

export interface RiskAssessment {
  score: number;
  verdict: Verdict;
  topRule?: DetectorResult;
}

export function assessRisk(
  detectorResults: DetectorResult[],
  botSignal: BotSignal | undefined,
  config: WafConfig
): RiskAssessment {
  const detectorScore = detectorResults.reduce((max, r) => Math.max(max, r.score), 0);
  const botScore = botSignal && !botSignal.isKnownGoodBot ? botSignal.score : 0;
  const primary = Math.max(detectorScore, botScore);
  const secondary = Math.min(detectorScore, botScore);
  const score = Math.min(100, Math.round(primary + secondary * 0.2));
  const topRule = detectorResults.sort((a, b) => b.score - a.score)[0];

  let verdict: Verdict = 'allow';
  if (score >= config.riskThresholdBlock) verdict = 'block';
  else if (score >= config.riskThresholdChallenge) verdict = 'challenge';
  else if (detectorResults.length > 0) verdict = 'log';

  if (config.mode === 'monitor' && verdict === 'block') verdict = 'log';

  return { score, verdict, topRule };
}
