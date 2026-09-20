// 极简事件发射器（浏览器 / Node 同构）。
export class EventEmitter {
  constructor() {
    this._listeners = new Map();
  }

  on(event, fn) {
    if (!this._listeners.has(event)) this._listeners.set(event, new Set());
    this._listeners.get(event).add(fn);
    return () => this.off(event, fn);
  }

  off(event, fn) {
    this._listeners.get(event)?.delete(fn);
  }

  emit(event, payload) {
    for (const fn of this._listeners.get(event) ?? []) {
      try { fn(payload); } catch (err) { console.error(`[event:${event}] listener error`, err); }
    }
  }
}

export const yieldToEventLoop = (ms = 0) =>
  new Promise((resolve) => setTimeout(resolve, ms));
