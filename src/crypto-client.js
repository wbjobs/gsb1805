// 主线程 -> Worker 的 RPC 客户端：Promise 化、超时保护、错误还原。
import { CryptoError } from './crypto-core.js';

const DEFAULT_TIMEOUT = 120_000; // 大批迁移时单次调用也可能较慢

export class CryptoClient {
  constructor(workerUrl) {
    this.worker = new Worker(workerUrl, { type: 'module' });
    this.pending = new Map();
    this.seq = 0;
    this.worker.onmessage = (e) => this._onMessage(e.data);
    this.worker.onerror = (e) => {
      this._rejectAll(new CryptoError('WORKER_ERROR', `加密 Worker 异常：${e.message}`));
    };
  }

  _onMessage({ id, ok, result, error }) {
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    clearTimeout(p.timer);
    if (ok) {
      p.resolve(result);
    } else {
      p.reject(new CryptoError(error.code, error.message));
    }
  }

  _rejectAll(err) {
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  call(op, params, timeout = DEFAULT_TIMEOUT) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new CryptoError('TIMEOUT', `加密操作超时：${op}`));
      }, timeout);
      this.pending.set(id, { resolve, reject, timer });
      this.worker.postMessage({ id, op, params });
    });
  }

  deriveKEK(params) { return this.call('deriveKEK', params); }
  generateDEK() { return this.call('generateDEK'); }
  wrapDEK(params) { return this.call('wrapDEK', params); }
  unwrapDEK(params) { return this.call('unwrapDEK', params); }
  encrypt(params) { return this.call('encrypt', params); }
  decrypt(params) { return this.call('decrypt', params); }
  reencryptBatch(params) { return this.call('reencryptBatch', params); }
  release(keyId) { return this.call('release', { keyId }); }
  releaseAll() { return this.call('releaseAll'); }

  terminate() {
    this._rejectAll(new CryptoError('TERMINATED', '加密 Worker 已终止'));
    this.worker.terminate();
  }
}
