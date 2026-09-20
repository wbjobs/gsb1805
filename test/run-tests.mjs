// Node 端测试：真实 Web Crypto（Node>=20 内置）+ 内存存储，验证全部验收标准。
// 运行：node test/run-tests.mjs
import assert from 'node:assert/strict';
import * as core from '../src/crypto-core.js';
import { KeyManager } from '../src/key-manager.js';

// ---- 与 CryptoClient 同接口的直连实现（无 Worker，便于 Node 测试）----
class DirectCrypto {
  constructor() { this.keys = new Map(); this.seq = 0; }
  _put(k) { const id = 'k' + (++this.seq); this.keys.set(id, k); return id; }
  _need(id) { const k = this.keys.get(id); if (!k) throw new Error('no handle ' + id); return k; }
  async deriveKEK({ password, salt, iterations }) {
    return this._put(await core.deriveKEK(password, core.toU8(salt), iterations));
  }
  async generateDEK() { return this._put(await core.generateDEK()); }
  async wrapDEK({ dekId, kekId }) { return core.wrapDEK(this._need(dekId), this._need(kekId)); }
  async unwrapDEK({ wrapped, iv, kekId }) {
    return this._put(await core.unwrapDEK(wrapped, iv, this._need(kekId)));
  }
  async encrypt({ dekId, plaintext }) { return core.encryptText(this._need(dekId), plaintext); }
  async decrypt({ dekId, ciphertext, iv }) {
    return core.decryptText(this._need(dekId), ciphertext, iv);
  }
  async reencryptBatch({ fromDekId, toDekId, items }) {
    const from = this._need(fromDekId), to = this._need(toDekId);
    return Promise.all(items.map(async (it) => {
      const pt = await core.decryptText(from, it.ciphertext, it.iv);
      return core.encryptText(to, pt);
    }));
  }
  async release(keyId) { this.keys.delete(keyId); return true; }
  async releaseAll() { this.keys.clear(); return true; }
}

// ---- 与 NoteStore 同接口的内存实现 ----
class MemoryStore {
  constructor() { this.meta = new Map(); this.keys = new Map(); this.notes = new Map(); this.seq = 0; }
  async getMeta(k) { return this.meta.get(k); }
  async setMeta(k, v) { this.meta.set(k, structuredClone(v)); }
  async deleteMeta(k) { this.meta.delete(k); }
  async getAllKeyRecords() { return [...this.keys.values()].map((r) => structuredClone(r)); }
  async putKeyRecord(r) { this.keys.set(r.version, structuredClone(r)); }
  async deleteKeyRecord(v) { this.keys.delete(v); }
  async putNote(n) { const id = ++this.seq; this.notes.set(id, { ...n, id }); return id; }
  async getNote(id) { return this.notes.get(id); }
  async getAllNotes() { return [...this.notes.values()].map((n) => ({ ...n })); }
  async deleteNote(id) { this.notes.delete(id); }
  async countNotes() { return this.notes.size; }
  async iterateNotes(afterId = 0, limit) {
    const all = [...this.notes.values()].filter((n) => n.id > afterId)
      .sort((a, b) => a.id - b.id).slice(0, limit);
    const lastId = all.length ? all[all.length - 1].id : afterId;
    return { notes: all.map((n) => ({ ...n })), lastId, done: afterId + limit > this.seq || all.length < limit };
  }
  async putNotesBatch(notes) { for (const n of notes) this.notes.set(n.id, { ...n }); }
}

// 事件收集器：waitFor('migration-done') 可等待异步事件
function makeEmitter() {
  const log = [];
  const waiters = [];
  const onEvent = (e) => {
    log.push(e);
    for (let i = waiters.length - 1; i >= 0; i--) {
      if (waiters[i].type === e.type) { waiters[i].resolve(e); waiters.splice(i, 1); }
    }
  };
  const waitFor = (type, timeout = 30_000) => {
    const hit = log.find((e) => e.type === type);
    if (hit) return Promise.resolve(hit);
    return new Promise((resolve, reject) => {
      waiters.push({ type, resolve });
      setTimeout(() => reject(new Error('等待事件超时: ' + type)), timeout);
    });
  };
  return { onEvent, waitFor, log };
}

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

// 1. 加密核心：往返 + 篡改检测
test('加密/解密往返与篡改检测', async () => {
  const kek = await core.deriveKEK('pw', core.randomBytes(16), 1000);
  const dek = await core.generateDEK();
  const { wrapped, iv } = await core.wrapDEK(dek, kek);
  const dek2 = await core.unwrapDEK(wrapped, iv, kek);
  const enc = await core.encryptText(dek2, '你好，世界');
  assert.equal(await core.decryptText(dek2, enc.ciphertext, enc.iv), '你好，世界');
  const bad = core.toU8(enc.ciphertext); bad[0] ^= 1;
  await assert.rejects(core.decryptText(dek2, bad, enc.iv), /解密失败/);
});

// 2. 初始化 + 错误口令解锁失败
test('初始化与错误口令提示', async () => {
  const store = new MemoryStore();
  const km = new KeyManager({ store, crypto: new DirectCrypto() });
  await km.setup('correct');
  const km2 = new KeyManager({ store, crypto: new DirectCrypto() });
  await assert.rejects(km2.unlock('wrong'), /口令错误|解包失败/);
  await km2.unlock('correct'); // 正确口令可解
});

// 3. 验收：轮换后旧笔记可解、新笔记用新密钥、旧密钥销毁
test('轮换后旧笔记可解，新笔记用新密钥', async () => {
  const store = new MemoryStore();
  const em = makeEmitter();
  const km = new KeyManager({ store, crypto: new DirectCrypto(), onEvent: em.onEvent });
  await km.setup('pw');
  const id1 = await store.putNote({ ...(await km.encryptNote('旧笔记')), updatedAt: 1 });
  await km.rotate();
  await em.waitFor('migration-done');
  const id2 = await store.putNote({ ...(await km.encryptNote('新笔记')), updatedAt: 2 });
  const n1 = await store.getNote(id1);
  const n2 = await store.getNote(id2);
  assert.equal(await km.decryptNote(n1), '旧笔记');       // 旧笔记可解
  assert.equal(await km.decryptNote(n2), '新笔记');
  assert.equal(n1.keyVersion, 2);                          // 旧数据已迁移到新密钥
  assert.equal(n2.keyVersion, 2);                          // 新笔记用新密钥
  assert.deepEqual((await store.getAllKeyRecords()).map((r) => r.version), [2]); // 旧密钥已销毁
});

// 4. 验收：迁移中断可续（模拟崩溃后重开自动续跑）
test('迁移中断后可续跑', async () => {
  const store = new MemoryStore();
  const em1 = makeEmitter();
  const km = new KeyManager({ store, crypto: new DirectCrypto(), batchSize: 10, onEvent: em1.onEvent });
  await km.setup('pw');
  for (let i = 0; i < 55; i++) {
    await store.putNote({ ...(await km.encryptNote('note-' + i)), updatedAt: i });
  }
  // 第一批完成后立刻“崩溃”（中止 = 进程被杀的最保守模拟：检查点已落盘）
  em1.waitFor('migration-progress').then(() => km.pauseMigration());
  await km.rotate();
  await em1.waitFor('migration-paused');
  const mid = await store.getMeta('migration');
  assert.equal(mid.done, false);
  assert.ok(mid.processed > 0 && mid.processed < 55, '应只迁移了一部分');
  // “重启”：全新 KeyManager + 新 crypto，从同一存储恢复
  const em2 = makeEmitter();
  const km2 = new KeyManager({ store, crypto: new DirectCrypto(), batchSize: 10, onEvent: em2.onEvent });
  await km2.unlock('pw'); // 解锁后自动续跑
  await em2.waitFor('migration-done');
  const notes = await store.getAllNotes();
  assert.ok(notes.every((n) => n.keyVersion === 2), '全部迁移到 v2');
  for (let i = 0; i < 55; i++) {
    assert.equal(await km2.decryptNote(notes.find((n) => n.id === i + 1)), 'note-' + i);
  }
  assert.equal(await store.getMeta('migration'), undefined);
});

// 5. 验收：异常有提示（坏数据隔离、旧密钥保留、事件上报）
test('损坏数据被隔离并上报，旧密钥保留', async () => {
  const store = new MemoryStore();
  const em = makeEmitter();
  const km = new KeyManager({ store, crypto: new DirectCrypto(), batchSize: 5, onEvent: em.onEvent });
  await km.setup('pw');
  const good = await store.putNote({ ...(await km.encryptNote('好的')), updatedAt: 1 });
  // 手动注入一条损坏记录（密文非法）
  const badId = await store.putNote({
    ciphertext: new Uint8Array([1, 2, 3]), iv: core.randomBytes(12), keyVersion: 1, updatedAt: 2,
  });
  await km.rotate();
  const evt = await em.waitFor('migration-error');
  assert.deepEqual(evt.failed, [badId]);                    // 异常有提示（事件上报）
  assert.ok((await store.getAllKeyRecords()).some((r) => r.version === 1)); // 旧密钥保留
  assert.equal((await store.getNote(good)).keyVersion, 2);  // 好数据已迁移
  assert.equal(await km.decryptNote(await store.getNote(good)), '好的');
  await assert.rejects(km.decryptNote(await store.getNote(badId)), /解密失败/);
});

// 6. 轮换同时更换口令
test('轮换时更换口令', async () => {
  const store = new MemoryStore();
  const em = makeEmitter();
  const km = new KeyManager({ store, crypto: new DirectCrypto(), onEvent: em.onEvent });
  await km.setup('old-pw');
  await store.putNote({ ...(await km.encryptNote('秘密')), updatedAt: 1 });
  await km.rotate({ newPassword: 'new-pw' });
  await em.waitFor('migration-done');
  const km2 = new KeyManager({ store, crypto: new DirectCrypto() });
  await assert.rejects(km2.unlock('old-pw'), /口令错误|解包失败/);
  await km2.unlock('new-pw');
  assert.equal(await km2.decryptNote((await store.getAllNotes())[0]), '秘密');
});

// 7. 验收：性能可接受（2000 条全量迁移计时）
test('性能：2000 条迁移耗时', async () => {
  const store = new MemoryStore();
  const em = makeEmitter();
  const km = new KeyManager({ store, crypto: new DirectCrypto(), batchSize: 200, onEvent: em.onEvent });
  await km.setup('pw');
  const t0 = performance.now();
  for (let i = 0; i < 2000; i++) {
    await store.putNote({ ...(await km.encryptNote(`perf-${i}-` + 'x'.repeat(100))), updatedAt: i });
  }
  const t1 = performance.now();
  await km.rotate();
  await em.waitFor('migration-done');
  const t2 = performance.now();
  console.log(`    写入 2000 条: ${(t1 - t0).toFixed(0)}ms，迁移 2000 条: ${(t2 - t1).toFixed(0)}ms`);
  assert.ok(t2 - t1 < 60_000, '迁移耗时应远低于 60s');
  assert.equal((await store.getAllNotes()).filter((n) => n.keyVersion === 2).length, 2000);
});

// ---- runner ----
let failed = 0;
for (const [name, fn] of tests) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed++;
    console.error(`  ✗ ${name}\n    ${e.message}`);
  }
}
console.log(failed ? `\n${failed} 个测试失败` : `\n全部 ${tests.length} 个测试通过`);
process.exit(failed ? 1 : 0);
