import type { Request } from 'express';

const AUTOMATION_MARKERS = [
  'headlesschrome', 'phantomjs', 'selenium', 'puppeteer', 'playwright',
  'webdriver', 'python-requests', 'scrapy', 'curl/', 'wget/', 'axios/', 'go-http-client'
];

const KNOWN_GOOD_BOTS = ['googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider'];

export interface BotSignal {
  score: number;
  reasons: string[];
  isKnownGoodBot: boolean;
}

export function analyzeBotSignals(req: Request): BotSignal {
  const ua = (req.headers['user-agent'] ?? '').toString().toLowerCase();
  const reasons: string[] = [];
  let score = 0;

  if (!ua) {
    score += 40;
    reasons.push('missing-user-agent');
  }

  for (const marker of AUTOMATION_MARKERS) {
    if (ua.includes(marker)) {
      score += 50;
      reasons.push(`automation-marker:${marker}`);
    }
  }

  const isKnownGoodBot = KNOWN_GOOD_BOTS.some((bot) => ua.includes(bot));

  if (!req.headers['accept-language'] && !isKnownGoodBot) {
    score += 15;
    reasons.push('missing-accept-language');
  }

  if (req.headers['sec-fetch-mode'] === undefined && req.headers['x-requested-with'] === undefined && !isKnownGoodBot) {
    score += 10;
    reasons.push('missing-fetch-metadata');
  }

  const secChUa = req.headers['sec-ch-ua'];
  if (ua.includes('chrome') && !secChUa && !isKnownGoodBot) {
    score += 25;
    reasons.push('chrome-ua-without-client-hints');
  }

  if (req.headers['x-devtools-emulate-network-conditions-client-id']) {
    score += 30;
    reasons.push('devtools-protocol-header');
  }

  return { score: Math.min(100, score), reasons, isKnownGoodBot };
}
