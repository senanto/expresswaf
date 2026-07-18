import type { Request, Response } from 'express';
import type { Plugin, PluginContext, ThreatEvent, Verdict } from '../types/index.js';
import type { EventBus } from './EventBus.js';

export class PluginManager {
  private plugins: Plugin[] = [];
  private ctx: PluginContext;

  constructor(ctx: PluginContext, private bus: EventBus) {
    this.ctx = ctx;
  }

  register(plugin: Plugin): this {
    this.plugins.push(plugin);
    plugin.onInit?.(this.ctx);
    return this;
  }

  runOnRequest(req: Request, res: Response): Verdict | undefined {
    for (const plugin of this.plugins) {
      const verdict = plugin.onRequest?.(req, res, this.ctx);
      if (verdict) return verdict;
    }
    return undefined;
  }

  runOnThreat(event: ThreatEvent): void {
    this.bus.emitTyped('threat', event);
    for (const plugin of this.plugins) plugin.onThreat?.(event, this.ctx);
  }
}
