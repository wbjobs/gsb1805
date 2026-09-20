import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createWorkerHandle } from '../src/worker.mjs';
import { MemoryStorage } from '../src/memory-adapter.mjs';
import { Vault } from '../src/vault.mjs';

const FAST_KDF = { iterations: 1000 };

function setupHandle() {
  const storage = new MemoryStorage();
  const handle = createWorkerHandle(() => new Vault(storage, { batchSize: 10, batchDelayMs: 0 }));
  const replies = [];
  const events = [];
  handle.onmessage = (ev) => {
    if (typeof ev.data.id === 'number') replies.push(ev.data);
    else events.push(ev.data);
  };
  const call = (method, ...args) => {
    const id = replies.length + 1;
    return handle.postMessage({ data: { id, method, args } }).then(() => {
      const reply = replies.find((r) => r.id === id);
      if (!reply) throw new Error(`no reply for ${method}`);
      if (!reply.ok) throw Object.assign(new Error(reply.error.message), { code: reply.error.code, name: reply.error.name });
      return reply.result;
    });
  };
  return { storage, handle, call, replies, events };
}

test('Worker 协议：RPC 往返 + 错误序列化 + 迁移事件转发', async () => {
  const { storage, call, events } = setupHandle();

  assert.equal(await call('isInitialized'), false);
  await call('initialize', 'pw1', FAST_KDF);
  await call('addNote', 'worker 中的笔记');
  const notes = await call('listNotes');
  assert.equal(notes.length, 1);
  assert.equal(notes[0].content, 'worker 中的笔记');

  // 错误被序列化为 {name, message, code}
  await assert.rejects(call('unlock', 'wrong-pw'), (err) => err.code === 'BAD_PASSWORD');

  // 未知方法
  await assert.rejects(call('nope'), (err) => err.code === 'UNKNOWN_METHOD');

  // 轮换触发的事件能透传到“主线程”
  const done = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('等待 migration:done 超时')), 4000);
    events.push = (item) => {
      Array.prototype.push.call(events, item);
      if (item.event === 'migration:done') { clearTimeout(timer); resolve(); }
    };
  });
  await call('rotatePassword', 'pw1', 'pw2', FAST_KDF);
  await done;

  const progressSeen = events.some((e) => e.event === 'migration:progress');
  assert.ok(progressSeen, '应转发 migration:progress 事件');

  // 同一份持久化数据：旧密码失效，新密码可解锁并读到全部笔记
  const reopened = new Vault(storage);
  await assert.rejects(reopened.unlock('pw1'), (e) => e.code === 'BAD_PASSWORD');
  await reopened.unlock('pw2');
  const all = await reopened.listNotes();
  assert.equal(all.length, 1);
  assert.equal(all[0].content, 'worker 中的笔记');
});
