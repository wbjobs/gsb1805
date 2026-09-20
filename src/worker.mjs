// Web Worker 入口：在后台线程持有 Vault，避免 PBKDF2 派生与批量加解密阻塞 UI。
//
// 协议（Structured Clone）：
//   主线程 -> Worker  { id, method, args }
//   Worker -> 主线程  { id, ok:true, result } | { id, ok:false, error:{name,message,code} }
//   Worker -> 主线程  { event, payload }（轮换 / 迁移进度等）

import { Vault } from './vault.mjs';
import { IdbStorage, StorageError } from './idb-adapter.mjs';

const VAULT_EVENTS = [
  'rotated',
  'locked',
  'migration:progress',
  'migration:paused',
  'migration:blocked',
  'migration:done',
  'migration:itemerror',
  'migration:error',
];

// 除事件外可远程调用的方法（getter 以 getXxx 形式暴露）。

export function serializeError(err) {
  return {
    name: err?.name || 'Error',
    message: err?.message || String(err),
    code: err?.code || null,
  };
}

// 创建与传输无关的协议处理器：注入 Vault 工厂与消息投递函数。
// 浏览器 Worker、Node 伪 Worker 测试共用同一份协议逻辑。
export function createProtocol(vaultFactory, post) {
  let vaultPromise = null;
  const getVault = () => {
    if (!vaultPromise) {
      vaultPromise = Promise.resolve(vaultFactory()).then((vault) => {
        for (const event of VAULT_EVENTS) {
          vault.on(event, (payload) => post({ event, payload }));
        }
        return vault;
      });
    }
    return vaultPromise;
  };

  return {
    VAULT_EVENTS,
    async onMessage(msg) {
      if (!msg || typeof msg.id !== 'number') return;
      try {
        const vault = await getVault();
        if (typeof vault[msg.method] !== 'function') {
          throw new StorageError('UNKNOWN_METHOD', `不支持的方法: ${msg.method}`);
        }
        const result = await vault[msg.method](...(msg.args || []));
        post({ id: msg.id, ok: true, result: result ?? null });
      } catch (err) {
        post({ id: msg.id, ok: false, error: serializeError(err) });
      }
    },
  };
}

// Node 测试用的伪 Worker：接口对齐浏览器 Worker（postMessage/onmessage/terminate）。
export function createWorkerHandle(vaultFactory) {
  let listener = null;
  const protocol = createProtocol(vaultFactory, (msg) => {
    listener?.({ data: msg });
  });
  return {
    async postMessage(msg) {
      await protocol.onMessage(msg?.data ? msg.data : msg);
    },
    get onmessage() { return listener; },
    set onmessage(fn) { listener = fn; },
    terminate() { listener = null; },
  };
}

// 浏览器 Worker 环境自举（self 上无 document）。
if (typeof self !== 'undefined' && typeof self.postMessage === 'function' && self.document === undefined) {
  const protocol = createProtocol(
    async () => {
      const storage = await IdbStorage.open();
      return new Vault(storage);
    },
    (msg) => self.postMessage(msg),
  );
  self.onmessage = (ev) => { protocol.onMessage(ev.data); };
}
