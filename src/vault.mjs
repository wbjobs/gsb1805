// Vault：对外的唯一门面，组合 Keyring + Storage + Migrator。
//
// 线程模型：浏览器中由 vault-client.mjs 放进 Web Worker 执行；主线程只收事件。
// 本文件不依赖 DOM / Worker，Node 中可直接运行（测试同一份实现）。

import { Keyring, KeyringError } from './keyring.mjs';
import { Migrator, MigrationError } from './migration.mjs';
import { encrypt, decrypt, randomBytes } from './crypto-core.mjs';
import { EventEmitter } from './events.mjs';

export class VaultLockedError extends Error {
  constructor(message = '保险库已锁定，请先解锁') {
    super(message);
    this.name = 'VaultLockedError';
    this.code = 'LOCKED';
  }
}

export class Vault extends EventEmitter {
  constructor(storage, { batchSize = 25, batchDelayMs = 4, concurrency = 4 } = {}) {
    super();
    this._storage = storage;
    this._keyring = null;
    this._migrator = new Migrator(storage);
    this._opts = { batchSize, batchDelayMs, concurrency };
    this._rotating = false;

    this._migrator.on('progress', (p) => this.emit('migration:progress', p));
    this._migrator.on('paused', (p) => this.emit('migration:paused', p));
    this._migrator.on('blocked', (p) => this.emit('migration:blocked', p));
    this._migrator.on('done', (p) => this.emit('migration:done', p));
    this._migrator.on('itemerror', (p) => this.emit('migration:itemerror', p));
    this._migrator.on('error', (err) => this.emit('migration:error', err));
  }

  async isInitialized() {
    const meta = await this._storage.getMeta();
    return Boolean(meta && meta.initialized);
  }

  async initialize(password, opts) {
    this._keyring = await Keyring.initialize(this._storage, password, opts);
    return { activeKid: this._keyring.activeKid };
  }

  async unlock(password) {
    this._keyring = await Keyring.unlock(this._storage, password);
    return { activeKid: this._keyring.activeKid };
  }

  lock() {
    this._keyring = null;
    this.emit('locked');
  }

  get isUnlocked() {
    return Boolean(this._keyring);
  }

  get activeKid() {
    this._requireUnlocked();
    return this._keyring.activeKid;
  }

  async getActiveKid() {
    this._requireUnlocked();
    return this._keyring.activeKid;
  }

  _requireUnlocked() {
    if (!this._keyring) throw new VaultLockedError();
  }

  static _newNoteId() {
    const rand = randomBytes(8).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
    return `note_${Date.now().toString(36)}_${rand}`;
  }

  async addNote(content, { id = Vault._newNoteId(), now = Date.now } = {}) {
    this._requireUnlocked();
    const envelope = await encrypt(this._keyring.activeDek, content, this._keyring.activeKid);
    const note = { id, envelope, createdAt: now(), updatedAt: now() };
    await this._storage.putNote(note);
    return id;
  }

  async getNote(id) {
    this._requireUnlocked();
    const note = await this._storage.getNote(id);
    if (!note) return null;
    const dek = this._keyring.getDek(note.envelope.kid);
    const content = await decrypt(dek, note.envelope);
    return { id, content, createdAt: note.createdAt, updatedAt: note.updatedAt };
  }

  async listNotes() {
    this._requireUnlocked();
    const records = await this._storage.listNotes();
    records.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    return Promise.all(records.map(async (note) => {
      const dek = this._keyring.getDek(note.envelope.kid);
      return {
        id: note.id,
        content: await decrypt(dek, note.envelope),
        createdAt: note.createdAt,
        updatedAt: note.updatedAt,
      };
    }));
  }

  async updateNote(id, content, { now = Date.now } = {}) {
    this._requireUnlocked();
    const note = await this._storage.getNote(id);
    if (!note) {
      const err = new Error('笔记不存在');
      err.code = 'NOT_FOUND';
      throw err;
    }
    // 更新即“就地升级”：新内容总是用当前活动密钥加密，减少迁移量。
    const envelope = await encrypt(this._keyring.activeDek, content, this._keyring.activeKid);
    await this._storage.putNote({ ...note, envelope, updatedAt: now() });
  }

  async deleteNote(id) {
    await this._storage.deleteNote(id);
  }

  async migrationState() {
    return this._storage.getMigrationState();
  }

  async migrationFailures() {
    return this._storage.listFailures();
  }

  async retryFailures() {
    await this._storage.clearFailures();
    return this.resumeMigration();
  }

  // 轮换主密码：先原子完成 KEK/DEK 轮换（此调用返回后旧笔记已可被新密码解开），
  // 再在后台分批迁移笔记。迁移被设计为可中断、可续跑。
  async rotatePassword(currentPassword, newPassword, opts = {}) {
    this._requireUnlocked();
    if (this._rotating) throw new MigrationError('ROTATION_BUSY', '已有轮换/迁移在进行中');
    this._rotating = true;
    try {
      const { newKid } = await this._keyring.rotate(currentPassword, newPassword, opts);
      this.emit('rotated', { activeKid: newKid });
      await this._runMigration(newKid, opts);
      return { activeKid: newKid };
    } finally {
      this._rotating = false;
    }
  }

  async resumeMigration(opts = {}) {
    this._requireUnlocked();
    const state = await this._storage.getMigrationState();
    if (!state) return null;
    await this._runMigration(null, opts);
    return this._storage.getMigrationState();
  }

  async _runMigration(targetKid, opts) {
    const merged = { ...this._opts, ...opts };
    try {
      return await this._migrator.run(this._keyring, {
        batchSize: merged.batchSize,
        batchDelayMs: merged.batchDelayMs,
        concurrency: merged.concurrency,
        targetKid,
      });
    } catch (err) {
      if (err instanceof MigrationError && err.code === 'ALREADY_RUNNING') throw err;
      // 其它致命错误已由迁移器落断点并转发事件；这里继续抛出供调用方提示。
      throw err;
    }
  }

  pauseMigration() {
    this._migrator.pause();
  }
}

export { KeyringError };
