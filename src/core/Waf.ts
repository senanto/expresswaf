import { randomUUID } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { Plugin, ThreatEvent, WafConfig, WafMiddleware } from '../types/index.js';
import { ConfigLoader } from './ConfigLoader.js';
import { createLogger } from './Logger.js';
import { EventBus } from './EventBus.js';
import { PluginManager } from './PluginManager.js';
import { DetectorEngine } from './DetectorEngine.js';
import { assessRisk } from './RiskEngine.js';
import { securityHeaders } from '../security/headers.js';
import { RateLimiter } from '../rateLimit/RateLimiter.js';
import { MemoryStore } from '../rateLimit/MemoryStore.js';
import { RedisStore } from '../rateLimit/RedisStore.js';
import { ipFilterMiddleware, DynamicBanList } from '../firewall/IpFilter.js';
import { analyzeBotSignals } from '../botDetection/heuristics.js';
import { ChallengeManager } from '../botDetection/Challenge.js';

export class Waf {
  readonly bus = new EventBus();
  readonly banList = new DynamicBanList();
  readonly challenge: ChallengeManager;
  private configLoader: ConfigLoader;
  private logger: ReturnType<typeof createLogger>;
  private detectorEngine: DetectorEngine;
  private pluginManager: PluginManager;
  private rateLimiter: RateLimiter;

  constructor(seed?: Partial<WafConfig>) {
    this.configLoader = new ConfigLoader(seed);
    this.logger = createLogger(this.config.logging);
    this.detectorEngine = new DetectorEngine(this.config);
    this.challenge = new ChallengeManager();
    this.pluginManager = new PluginManager(
      { config: this.config, logger: this.logger, emit: (e, p) => this.bus.emit(e, p) },
      this.bus
    );
    this.rateLimiter = new RateLimiter(new MemoryStore());
    this.upgradeStoreIfNeeded();
    this.configLoader.onChange((next) => {
      this.detectorEngine = new DetectorEngine(next);
      this.bus.emitTyped('config:reload', next);
      this.upgradeStoreIfNeeded();
    });
  }

  private upgradeStoreIfNeeded(): void {
    if (this.config.rateLimit.store !== 'redis' || !this.config.rateLimit.redisUrl) return;
    RedisStore.connect(this.config.rateLimit.redisUrl)
      .then((store) => {
        this.rateLimiter = new RateLimiter(store);
      })
      .catch((err) => this.logger.warn({ err: String(err) }, 'redis_connect_failed_falling_back_to_memory'));
  }

  get config(): WafConfig {
    return this.configLoader.config;
  }

  use(plugin: Plugin): this {
    this.pluginManager.register(plugin);
    return this;
  }

  async loadConfigFile(path: string): Promise<void> {
    await this.configLoader.loadFromFile(path, this.config.hotReload);
    this.detectorEngine = new DetectorEngine(this.config);
  }

  middleware(): WafMiddleware {
    const headerMw = securityHeaders(this.config.headers);
    const ipMw = ipFilterMiddleware(this.config.ipFilter);
    const banMw = this.banList.middleware();

    return async (req: Request, res: Response, next: NextFunction) => {
      const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
      this.bus.emitTyped('request:start', { ip, path: req.path });

      headerMw(req, res, () => {});
      let blocked = false;
      ipMw(req, res, () => {});
      if (res.headersSent) return;
      banMw(req, res, () => {});
      if (res.headersSent) return;

      const pluginVerdict = this.pluginManager.runOnRequest(req, res);
      if (pluginVerdict === 'block') {
        res.status(403).json({ error: 'blocked_by_plugin' });
        return;
      }

      const detectorResults = this.detectorEngine.scanRequest(req, this.config);
      const botSignal = this.config.botDetection.enabled ? analyzeBotSignals(req) : undefined;
      const risk = assessRisk(detectorResults, botSignal, this.config);

      if (detectorResults.length > 0 || risk.verdict !== 'allow') {
        const event: ThreatEvent = {
          id: randomUUID(),
          timestamp: Date.now(),
          ip,
          method: req.method,
          path: req.path,
          category: risk.topRule?.category ?? 'bot',
          rule: risk.topRule?.rule ?? botSignal?.reasons.join(',') ?? 'heuristic',
          riskScore: risk.score,
          verdict: risk.verdict,
          meta: { detectorResults, botSignal }
        };
        this.pluginManager.runOnThreat(event);
        this.logger.warn({ event }, 'threat_detected');

        if (risk.verdict === 'block') {
          this.bus.emitTyped('block', event);
          res.status(403).json({ error: 'request_blocked', requestId: event.id });
          blocked = true;
        } else if (risk.verdict === 'challenge' && this.config.botDetection.challengeSuspicious) {
          this.bus.emitTyped('challenge', event);
          if (!this.challenge.hasValidCookie(req)) {
            res.setHeader('Set-Cookie', this.challenge.cookieHeader());
            this.challenge.renderChallengePage(res, randomUUID());
            blocked = true;
          }
        }
      }

      if (!blocked) next();
    };
  }

  rateLimit(rule: WafConfig['rateLimit']['global'] = this.config.rateLimit.global): WafMiddleware {
    return this.rateLimiter.middleware(rule) as WafMiddleware;
  }
}
