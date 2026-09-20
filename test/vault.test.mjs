import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { MemoryStorage } from '../src/memory-adapter.mjs';
import { Vault } from '../src/vault.mjs';
import { Keyring } from '../src/keyring.mjs';
import { Migrator } from '../src/migration.mjs';
import { decrypt } from '../src/crypto-core.mjs';

const FAST_KDF = { iterations: 1000 };

async function freshVault(opts = {}) {
  const storage = new MemoryStorage();
  const vault = new Vault(storage, { batchSize: 10, batchDelayMs: 0, concurrency: 4, ...opts });
  return { storage, vault };
}

async function seed(vault, contents, password = 'pw-initial') {
  await vault.initialize(password, FAST_KDF);
  const ids = [];
  for (const text of contents) ids.push(await vault.addNote(text));
  return ids;
}

describe('初始化与解锁', () => {
  let storage;
  beforeEach(() => { storage = new MemoryStorage(); });

  test('首次初始化后可用密码解锁，错误密码被拒绝', async () => {
    const v1 = new Vault(storage);
    await v1.initialize('correct horse', FAST_KDF);
    await v1.addNote('秘密');

    const v2 = new Vault(storage);
    await assert.rejects(v2.unlock('wrong horse'), (err) => err.code === 'BAD_PASSWORD');

    const v3 = new Vault(storage);
    await v3.unlock('correct horse');
    const notes = await v3.listNotes();
    assert.equal(notes.length, 1);
    assert.equal(notes[0].content, '秘密');
  });

  test('重复初始化被拒绝', async () => {
    const v = new Vault(storage);
    await v.initialize('a', FAST_KDF);
    await assert.rejects(v.initialize('b', FAST_KDF), (err) => err.code === 'ALREADY_INITIALIZED');
  });

  test('未初始化时解锁抛出 NOT_INITIALIZED', async () => {
    const v = new Vault(storage);
    await assert.rejects(v.unlock('x'), (err) => err.code === 'NOT_INITIALIZED');
  });
});

describe('密钥轮换（验收：旧笔记可解 / 新笔记用新密钥）', () => {
  test('轮换后：旧笔记用新密码可解，新笔记使用新 kid，旧密码失效', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage, { batchSize: 10, batchDelayMs: 0 });
    const ids = await seed(vault, ['旧笔记1', '旧笔记2', '旧笔记3']);
    const oldKid = vault.activeKid;

    const progressEvents = [];
    vault.on('migration:progress', (p) => progressEvents.push(p));
    const done = new Promise((resolve) => vault.on('migration:done', resolve));

    await vault.rotatePassword('pw-initial', 'pw-rotated', FAST_KDF);
    await done;

    const newKid = vault.activeKid;
    assert.notEqual(newKid, oldKid);
    assert.ok(progressEvents.length >= 1);

    // 1) 新笔记使用新密钥
    const newId = await vault.addNote('轮换后的新笔记');
    const rawNew = await storage.getNote(newId);
    assert.equal(rawNew.envelope.kid, newKid);

    // 2) 旧笔记也已被后台迁移到新 kid，且内容正确
    for (const id of ids) {
      const raw = await storage.getNote(id);
      assert.equal(raw.envelope.kid, newKid);
      assert.equal(await vault.getNote(id).then((n) => n.content), '旧笔记' + (ids.indexOf(id) + 1));
    }

    // 3) 旧密钥版本已清理，存储里只剩活动版本
    const remainingKeys = await storage.listKeys();
    assert.deepEqual(remainingKeys.map((k) => k.id), [newKid]);

    // 4) 旧密码不能再解锁；新密码可以
    const vOld = new Vault(storage);
    await assert.rejects(vOld.unlock('pw-initial'), (e) => e.code === 'BAD_PASSWORD');
    const vNew = new Vault(storage);
    await vNew.unlock('pw-rotated', FAST_KDF);
    const all = await vNew.listNotes();
    assert.equal(all.length, 4);
  });

  test('当前密码错误时轮换被拒绝，数据不受影响', async () => {
    const { vault } = await freshVault();
    await seed(vault, ['x']);
    const kid = vault.activeKid;
    await assert.rejects(
      vault.rotatePassword('wrong-current', 'new-pw', FAST_KDF),
      (e) => e.code === 'BAD_PASSWORD',
    );
    assert.equal(vault.activeKid, kid);
    assert.equal((await vault.listNotes())[0].content, 'x');
  });

  test('轮换提交后、迁移完成前：新密码即可解开旧笔记（重包装先于迁移）', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage, { batchSize: 100, batchDelayMs: 0 });
    await vault.initialize('pw1', FAST_KDF);
    for (let i = 0; i < 5; i += 1) await vault.addNote(`n${i}`);

    // 手动做“只轮换密钥、不迁移”：直接调用 keyring.rotate，模拟轮换刚提交的瞬间。
    const { newKid } = await vault._keyring.rotate('pw1', 'pw2', FAST_KDF);

    // 用新密码解锁一个全新的 Vault：旧 DEK 已被新 KEK 重包装，因此旧笔记可解。
    const v2 = new Vault(storage);
    await v2.unlock('pw2');
    const notes = await v2.listNotes();
    assert.equal(notes.length, 5);
    assert.ok(notes.every((n) => n.content.startsWith('n')));
    assert.equal(v2.activeKid, newKid);
  });
});

describe('迁移中断与续跑（验收：迁移中断可续）', () => {
  test('迁移中途暂停：断点落库；续跑后全部完成且内容无损', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage, { batchSize: 1, batchDelayMs: 0, concurrency: 1 });
    const contents = Array.from({ length: 25 }, (_, i) => `笔记 ${i}`);
    const ids = await seed(vault, contents);
    const oldKid = vault.activeKid;

    const { newKid } = await vault._keyring.rotate('pw-initial', 'pw2', FAST_KDF);

    // 第一批（1 条）完成后立即暂停
    const migrator = new Migrator(storage);
    let pausedOnce = false;
    migrator.on('progress', () => { if (!pausedOnce) { pausedOnce = true; migrator.pause(); } });
    const state1 = await migrator.run(vault._keyring, { batchSize: 1, batchDelayMs: 0, concurrency: 1, targetKid: newKid });
    assert.equal(state1.status, 'paused');
    assert.equal(state1.targetKid, newKid);
    assert.equal(state1.migratedCount, 1);

    // 断点已持久化：新建迁移器从同一存储恢复
    const persisted = await storage.getMigrationState();
    assert.equal(persisted.targetKid, newKid);
    assert.equal(persisted.migratedCount, 1);

    // 部分旧 kid、部分新 kid 混合存在，两种都能解密
    const migrated = await storage.countNotesByKid(newKid);
    const stillOld = await storage.countNotesByKid(oldKid);
    assert.equal(migrated, 1);
    assert.equal(stillOld, 24);

    const mid = new Vault(storage);
    await mid.unlock('pw2');
    assert.equal((await mid.listNotes()).length, 25);

    // 续跑到完成
    const migrator2 = new Migrator(storage);
    const state2 = await migrator2.run(mid._keyring, { batchSize: 5, batchDelayMs: 0, concurrency: 2 });
    assert.equal(state2.status, 'done');
    assert.equal(await storage.countNotesByKid(newKid), 25);
    assert.equal(await storage.countNotesByKid(oldKid), 0);
    assert.equal(await storage.getMigrationState(), null);

    // 全部内容无损
    const after = (await mid.listNotes()).map((n) => n.content).sort();
    assert.deepEqual(after, contents.sort());
    for (const id of ids) assert.ok(await storage.getNote(id));
  });

  test('跨“会话”续跑：用新密码重新解锁后 resumeMigration 成功', async () => {
    const storage = new MemoryStorage();
    const v1 = new Vault(storage, { batchSize: 2, batchDelayMs: 0 });
    await v1.initialize('pw1', FAST_KDF);
    for (let i = 0; i < 10; i += 1) await v1.addNote(`c${i}`);
    const { newKid } = await v1._keyring.rotate('pw1', 'pw2', FAST_KDF);

    const m1 = new Migrator(storage);
    m1.on('progress', () => m1.pause());
    await m1.run(v1._keyring, { batchSize: 2, batchDelayMs: 0, targetKid: newKid });

    // 模拟重新打开应用：新 Vault、用新密码解锁，自动续迁
    const v2 = new Vault(storage, { batchSize: 3, batchDelayMs: 0 });
    await v2.unlock('pw2');
    const state = await v2.resumeMigration();
    assert.equal(state, null); // 完成后断点清除
    assert.equal(await storage.countNotesByKid(newKid), 10);
    const notes = await v2.listNotes();
    assert.equal(notes.length, 10);
  });
});

  test('同一迁移器上“暂停 -> 继续”可跑到完成', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage, { batchSize: 2, batchDelayMs: 0, concurrency: 1 });
    await vault.initialize('pw1', FAST_KDF);
    for (let i = 0; i < 12; i += 1) await vault.addNote(`m${i}`);
    const { newKid } = await vault._keyring.rotate('pw1', 'pw2', FAST_KDF);

    const migrator = new Migrator(storage);
    let pauses = 0;
    migrator.on('progress', () => { if (pauses < 2) { pauses += 1; migrator.pause(); } });

    const s1 = await migrator.run(vault._keyring, { batchSize: 2, batchDelayMs: 0, concurrency: 1, targetKid: newKid });
    assert.equal(s1.status, 'paused');
    assert.equal(s1.migratedCount, 2);

    const s2 = await migrator.run(vault._keyring, { batchSize: 2, batchDelayMs: 0, concurrency: 1 });
    assert.equal(s2.status, 'paused');
    assert.equal(s2.migratedCount, 4);

    const s3 = await migrator.run(vault._keyring, { batchSize: 5, batchDelayMs: 0, concurrency: 2 });
    assert.equal(s3.status, 'done');
    assert.equal(await storage.countNotesByKid(newKid), 12);
  });

describe('更新即升级', () => {
  test('迁移期间更新旧笔记会直接用活动密钥加密，减少迁移量', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage);
    await vault.initialize('pw', FAST_KDF);
    const id = await vault.addNote('旧内容');
    const oldKid = vault.activeKid;
    await vault._keyring.rotate('pw', 'pw2', FAST_KDF);
    const newKid = vault.activeKid;

    await vault.updateNote(id, '更新后的内容');
    assert.equal((await storage.getNote(id)).envelope.kid, newKid);
    assert.equal((await vault.getNote(id)).content, '更新后的内容');
    assert.equal(await storage.countNotesByKid(oldKid), 0);
  });
});

describe('异常处理（验收：异常有提示/不丢数据）', () => {
  test('密文被篡改时解密抛 DECRYPT_FAILED，错误可识别', async () => {
    const { storage, vault } = await freshVault();
    await vault.initialize('pw', FAST_KDF);
    const id = await vault.addNote('abc');
    const raw = await storage.getNote(id);
    raw.envelope.ct[0] ^= 0xff;
    await storage.putNote(raw);
    await assert.rejects(vault.getNote(id), (e) => e.code === 'DECRYPT_FAILED');
  });

  test('迁移单条失败不阻塞其它笔记，失败有记录且旧密钥保留', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage, { batchSize: 10, batchDelayMs: 0 });
    await vault.initialize('pw', FAST_KDF);
    const ids = [];
    for (let i = 0; i < 6; i += 1) ids.push(await vault.addNote(`ok-${i}`));
    const oldKid = vault.activeKid;
    const { newKid } = await vault._keyring.rotate('pw', 'pw2', FAST_KDF);

    // 破坏其中一条旧密文
    const bad = ids[2];
    const badRaw = await storage.getNote(bad);
    badRaw.envelope.ct[0] ^= 0xff;
    await storage.putNote(badRaw);

    const errors = [];
    const migrator = new Migrator(storage);
    migrator.on('itemerror', (p) => errors.push(p));
    const state = await migrator.run(vault._keyring, {
      batchSize: 3, batchDelayMs: 0, concurrency: 1, targetKid: newKid,
    });

    assert.equal(errors.length, 1);
    assert.equal(errors[0].id, bad);
    // 未全部成功：状态保持 paused，旧密钥保留，坏笔记仍是旧 kid
    assert.equal(state.status, 'paused');
    assert.equal(await storage.countNotesByKid(newKid), 5);
    assert.equal(await storage.countNotesByKid(oldKid), 1);
    const keyIds = (await storage.listKeys()).map((k) => k.id).sort();
    assert.ok(keyIds.includes(oldKid) && keyIds.includes(newKid));

    // 修复坏数据（模拟）：恢复原始内容后重试可完成
    const oldDek = vault._keyring.getDek(oldKid);
    // 直接把坏笔记更新成活动密钥下的合法密文，模拟用户重新编辑
    await vault.updateNote(bad, 'ok-2');
    const failures = await storage.listFailures();
    assert.ok(failures.some((f) => f.id === bad));
    await storage.clearFailures();
    const migrator2 = new Migrator(storage);
    const state2 = await migrator2.run(vault._keyring, { batchSize: 3, batchDelayMs: 0 });
    assert.equal(state2.status, 'done');
    assert.equal((await vault.getNote(bad)).content, 'ok-2');
  });

  test('存储层抛错时迁移断点保留、事件上报，不会无限重试', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage, { batchSize: 2, batchDelayMs: 0 });
    await vault.initialize('pw', FAST_KDF);
    for (let i = 0; i < 4; i += 1) await vault.addNote(`x${i}`);
    const { newKid } = await vault._keyring.rotate('pw', 'pw2', FAST_KDF);

    storage.getNote = () => { throw new Error('模拟存储故障'); };
    const migrator = new Migrator(storage);
    const itemErrors = [];
    migrator.on('itemerror', (p) => itemErrors.push(p));
    const state = await migrator.run(vault._keyring, {
      batchSize: 2, batchDelayMs: 0, concurrency: 2, targetKid: newKid,
    });
    assert.equal(itemErrors.length, 4);
    assert.equal(state.targetKid, newKid);
    assert.equal(state.status, 'paused');
  });
});

describe('性能（验收：性能可接受）', async () => {
  test('100 条笔记的轮换+迁移在合理时间内完成（含 1 次 PBKDF2-1000）', async () => {
    const storage = new MemoryStorage();
    const vault = new Vault(storage, { batchSize: 25, batchDelayMs: 0, concurrency: 8 });
    await vault.initialize('pw', FAST_KDF);
    const payload = '机密'.repeat(500);
    for (let i = 0; i < 100; i += 1) await vault.addNote(`${i}:${payload}`);

    const t0 = Date.now();
    await vault.rotatePassword('pw', 'pw2', FAST_KDF);
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 5000, `迁移耗时 ${elapsed}ms 超过 5s 预算`);
  });
});
