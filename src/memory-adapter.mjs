// 与 IdbStorage 同构的内存适配器：用于 Node 测试，也可在不支持 IndexedDB 的
// 降级环境中使用。所有方法均为异步，语义与 IndexedDB 版本保持一致。

const ROOT = 'root';
const ACTIVE = 'active';
const microtask = () => new Promise((resolve) => setTimeout(resolve, 0));

export class MemoryStorage {
  constructor() {
    this._notes = new Map();
    this._meta = null;
    this._keys = new Map();
    this._migration = null;
    this._failures = new Map();
  }

  async close() { /* no-op */ }

  async getMeta() {
    await microtask();
    return this._meta;
  }

  async saveMeta(meta) {
    await microtask();
    this._meta = { ...meta, id: ROOT };
  }

  async listKeys() {
    await microtask();
    return [...this._keys.values()];
  }

  async saveKey(keyVersion) {
    await microtask();
    this._keys.set(keyVersion.id, { ...keyVersion });
  }

  async deleteKey(kid) {
    await microtask();
    this._keys.delete(kid);
  }

  async commitRotation({ newVersion, rewrapped, newActiveKid, newVerifier }) {
    await microtask();
    // 模拟单事务：先在影子副本上完成所有变更，最后一起提交。
    if (!this._meta) {
      const err = new Error('元数据缺失，仓库未初始化');
      err.code = 'NO_META';
      throw err;
    }
    const keys = new Map(this._keys);
    keys.set(newVersion.id, { ...newVersion });
    for (const kv of rewrapped) keys.set(kv.id, { ...kv });
    this._keys = keys;
    this._meta = { ...this._meta, activeKid: newActiveKid, verifier: newVerifier };
  }

  async putNote(note) {
    await microtask();
    this._notes.set(note.id, { ...note });
  }

  async getNote(id) {
    await microtask();
    return this._notes.get(id);
  }

  async listNotes() {
    await microtask();
    return [...this._notes.values()].map((n) => ({ ...n }));
  }

  async deleteNote(id) {
    await microtask();
    this._notes.delete(id);
  }

  async countNotesByKid(kid) {
    await microtask();
    let n = 0;
    for (const note of this._notes.values()) {
      if (note.envelope && note.envelope.kid === kid) n += 1;
    }
    return n;
  }

  async listStaleNoteIds(activeKid, afterId = null, limit = 50) {
    await microtask();
    const stale = [...this._notes.values()]
      .filter((note) => note.envelope && note.envelope.kid !== activeKid)
      .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
      .map((note) => note.id);
    const start = afterId ? stale.indexOf(afterId) + 1 : 0;
    return stale.slice(start, start + limit);
  }

  async getMigrationState() {
    await microtask();
    return this._migration;
  }

  async saveMigrationState(state) {
    await microtask();
    this._migration = { ...state, id: ACTIVE };
  }

  async clearMigrationState() {
    await microtask();
    this._migration = null;
  }

  async listFailures() {
    await microtask();
    return [...this._failures.values()];
  }

  async saveFailure(failure) {
    await microtask();
    this._failures.set(failure.id, { ...failure });
  }

  async clearFailures() {
    await microtask();
    this._failures.clear();
  }
}
