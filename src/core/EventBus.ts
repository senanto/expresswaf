import { EventEmitter } from 'node:events';
import type { ThreatEvent } from '../types/index.js';

export interface WafEvents {
  threat: (event: ThreatEvent) => void;
  block: (event: ThreatEvent) => void;
  challenge: (event: ThreatEvent) => void;
  'config:reload': (config: unknown) => void;
  'request:start': (payload: { ip: string; path: string }) => void;
}

export class EventBus extends EventEmitter {
  emitTyped<K extends keyof WafEvents>(event: K, ...args: Parameters<WafEvents[K]>): void {
    this.emit(event as string, ...args);
  }
  onTyped<K extends keyof WafEvents>(event: K, listener: WafEvents[K]): void {
    this.on(event as string, listener as (...args: unknown[]) => void);
  }
}
