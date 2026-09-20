// Web Worker：所有加解密/密钥派生都在这里执行，避免阻塞 UI。
// CryptoKey 句柄不出 Worker，主线程只持有不透明 keyId，降低密钥泄露面。
import * as core from './crypto-core.js';

const keys = new Map(); // keyId -> CryptoKey
let seq = 0;

function put(key) {
  const id = 'k' + (++seq);
  keys.set(id, key);
  return id;
}

function need(id) {
  const k = keys.get(id);
  if (!k) throw new core.CryptoError('KEY_HANDLE_MISSING', `密钥句柄不存在：${id}`);
  return k;
}

const ops = {
  async deriveKEK({ password, salt, iterations }) {
    return put(await core.deriveKEK(password, core.toU8(salt), iterations));
  },
  async generateDEK() {
    return put(await core.generateDEK());
  },
  async wrapDEK({ dekId, kekId }) {
    return core.wrapDEK(need(dekId), need(kekId));
  },
  async unwrapDEK({ wrapped, iv, kekId }) {
    return put(await core.unwrapDEK(wrapped, iv, need(kekId)));
  },
  async encrypt({ dekId, plaintext }) {
    return core.encryptText(need(dekId), plaintext);
  },
  async decrypt({ dekId, ciphertext, iv }) {
    return core.decryptText(need(dekId), ciphertext, iv);
  },
  // 迁移热路径：整批一次 postMessage，批内并行，显著降低通信开销
  async reencryptBatch({ fromDekId, toDekId, items }) {
    const from = need(fromDekId);
    const to = need(toDekId);
    return Promise.all(items.map(async (it) => {
      const pt = await core.decryptText(from, it.ciphertext, it.iv);
      return core.encryptText(to, pt);
    }));
  },
  async release({ keyId }) {
    keys.delete(keyId);
    return true;
  },
  async releaseAll() {
    keys.clear();
    return true;
  },
};

self.onmessage = async (e) => {
  const { id, op, params } = e.data;
  try {
    if (!ops[op]) throw new core.CryptoError('BAD_OP', `未知操作：${op}`);
    const result = await ops[op](params || {});
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({
      id,
      ok: false,
      error: {
        name: err.name || 'Error',
        code: err.code || 'UNKNOWN',
        message: err.message || String(err),
      },
    });
  }
};
