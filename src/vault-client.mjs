// 主线程 Vault 代理：优先通过 Web Worker 与后台 Vault 通信；
// Worker 构造失败（file://、旧浏览器等）时降级为主线程内存实现，保证功能可用。

import { Vault } from './vault.mjs';
import { MemoryStorage } from './memory-adapter.mjs';
import { EventEmitter } from './events.mjs';

export class RpcError extends Error {
  constructor({ name, message, code }) {
    super(message);
    this.name = name || 'RpcError';
    this.code = code || null;
  }
}

// 按 Worker 代理的同名事件集合。
const PROXIED_EVENTS = [
  'rotated',
  'locked',
  'migration:progress',
  'migration:paused',
  'migration:blocked',
  'migration:done',
  'migration:itemerror',
  'migration:error',
];

const PROXIED_METHODS = [
  'isInitialized',
  'initialize',
  'unlock',
  'lock',
  'getActiveKid',
  'addNote',
  'getNote',
  'listNotes',
  'updateNote',
  'deleteNote',
  'migrationState',
  'migrationFailures',
  'retryFailures',
  'rotatePassword',
  'resumeMigration',
  'pauseMigration',
];

class WorkerBackend extends EventEmitter {
  constructor(workerUrl) {
    super();
    this._worker = new Worker(workerUrl, { type: 'module' });
    this._seq = 0;
    this._pending = new Map();
    this._worker.onmessage = (ev) => this._onMessage(ev.data);
    this._worker.onerror = (ev) => {
      this._failAll(new RpcError({
        name: 'WorkerError',
        message: ev.message || 'Worker 内部错误（模块加载失败？）',
        code: 'WORKER_ERROR',
      }));
      this.emit('backend:error', new Error(ev.message || 'Worker 内部错误'));
    };
    this._worker.onmessageerror = () => {
      this._failAll(new RpcError({ message: 'Worker 消息反序列化失败', code: 'WORKER_MESSAGE_ERROR' }));
    };
  }

  _failAll(err) {
    for (const entry of this._pending.values()) entry.reject(err);
    this._pending.clear();
  }

  _onMessage(msg) {
    if (!msg) return;
    if (typeof msg.id === 'number') {
      const entry = this._pending.get(msg.id);
      if (!entry) return;
      this._pending.delete(msg.id);
      if (msg.ok) entry.resolve(msg.result);
      else entry.reject(new RpcError(msg.error || {}));
      return;
    }
    if (msg.event) this.emit(msg.event, msg.payload);
  }

  call(method, args) {
    const id = (this._seq += 1);
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      this._worker.postMessage({ id, method, args });
    });
  }

  terminate() {
    for (const { reject } of this._pending.values()) {
      reject(new RpcError({ message: 'Worker 已终止', code: 'TERMINATED' }));
    }
    this._pending.clear();
    this._worker.terminate();
  }
}

class MainThreadBackend extends EventEmitter {
  constructor(storageFactory) {
    super();
    this._vault = new Vault(storageFactory());
    for (const event of PROXIED_EVENTS) {
      this._vault.on(event, (payload) => this.emit(event, payload));
    }
  }

  call(method, args) {
    return Promise.resolve(this._vault[method](...args));
  }

  terminate() { /* no-op */ }
}

export class VaultClient extends EventEmitter {
  constructor(backend) {
    super();
    this._backend = backend;
    for (const event of PROXIED_EVENTS) {
      this._backend.on(event, (payload) => this.emit(event, payload));
    }
    for (const method of PROXIED_METHODS) {
      this[method] = (...args) => this._backend.call(method, args);
    }
  }

  get isWorkerBackend() {
    return this._backend instanceof WorkerBackend;
  }

  // workerUrl 默认为同目录 worker.mjs（打包后可用构建产物路径覆盖）。
  static async create(workerUrl = new URL('./worker.mjs', import.meta.url)) {
    try {
      if (typeof Worker !== 'function') throw new Error('no Worker');
      const backend = new WorkerBackend(workerUrl);
      // 用一次低成本往返确认 Worker 真的能跑起来（模块路径错误会在这里暴露）。
      await backend.call('isInitialized');
      return new VaultClient(backend);
    } catch (err) {
      console.warn('[vault] Worker 不可用，降级到主线程模式：', err);
      const { IdbStorage } = await import('./idb-adapter.mjs').catch(() => ({}));
      let storage;
      try {
        if (IdbStorage) storage = await IdbStorage.open();
        else throw new Error('no idb');
      } catch {
        storage = new MemoryStorage();
      }
      return new VaultClient(new MainThreadBackend(() => storage));
    }
  }
}
