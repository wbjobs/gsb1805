// IndexedDB 存储适配层。
//
// Object Stores:
//   notes      加密笔记：{ id, envelope, updatedAt }，keyPath=id，index: by-updatedAt
//   meta       单条配置（identityKey 固定为 'root'）：{ id:'root', initialized, activeKid, verifier, createdAt }
//   keys       密钥版本：KeyVersion 记录，keyPath=id
//   migration  迁移断点：固定一条 { id:'active', ... }
//   failures   迁移失败记录：{ id(noteId), error, at }，keyPath=id
//
// 所有写入均为单事务原子操作；“整体重包装”由 rotatePassword 用一个
// readwrite(keys,meta) 事务完成。

const DB_NAME = 'notes-vault';
const DB_VERSION = 1;
const ROOT = 'root';
const ACTIVE = 'active';

export class StorageError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'StorageError';
    this.code = code;
    if (cause) this.cause = cause;
  }
}

function openDb() {
  if (typeof indexedDB === 'undefined') {
    throw new StorageError('NO_INDEXEDDB', '当前环境不支持 IndexedDB');
  }
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('notes')) {
        const store = db.createObjectStore('notes', { keyPath: 'id' });
        store.createIndex('by-updatedAt', 'updatedAt');
      }
      if (!db.objectStoreNames.contains('meta')) {
        db.createObjectStore('meta', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('migration')) {
        db.createObjectStore('migration', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('failures')) {
        db.createObjectStore('failures', { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(new StorageError('IDB_OPEN', '数据库打开失败', req.error));
    req.onblocked = () => reject(new StorageError('IDB_BLOCKED', '数据库被其它标签页阻塞，请关闭旧标签页后重试'));
  });
}

function reqPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new StorageError('IDB_OP', '数据库操作失败', request.error));
  });
}

function txPromise(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new StorageError('IDB_TX', '数据库事务失败', tx.error));
    tx.onabort = () => reject(new StorageError('IDB_ABORT', '数据库事务中止', tx.error));
  });
}

export class IdbStorage {
  constructor(db) {
    this._db = db;
  }

  static async open() {
    return new IdbStorage(await openDb());
  }

  close() {
    try { this._db.close(); } catch { /* ignore */ }
  }

  async getMeta() {
    const tx = this._db.transaction('meta', 'readonly');
    return reqPromise(tx.objectStore('meta').get(ROOT));
  }

  async saveMeta(meta) {
    const tx = this._db.transaction('meta', 'readwrite');
    tx.objectStore('meta').put({ ...meta, id: ROOT });
    await txPromise(tx);
  }

  async listKeys() {
    const tx = this._db.transaction('keys', 'readonly');
    return reqPromise(tx.objectStore('keys').getAll());
  }

  async saveKey(keyVersion) {
    const tx = this._db.transaction('keys', 'readwrite');
    tx.objectStore('keys').put(keyVersion);
    await txPromise(tx);
  }

  async deleteKey(kid) {
    const tx = this._db.transaction('keys', 'readwrite');
    tx.objectStore('keys').delete(kid);
    await txPromise(tx);
  }

  // 原子轮换：同一事务内写入新版本、改写旧版本的 wrappedDek、切换 activeKid。
  async commitRotation({ newVersion, rewrapped, newActiveKid, newVerifier }) {
    const tx = this._db.transaction(['keys', 'meta'], 'readwrite');
    const keysStore = tx.objectStore('keys');
    keysStore.put(newVersion);
    for (const kv of rewrapped) {
      keysStore.put(kv);
    }
    const metaStore = tx.objectStore('meta');
    const getReq = metaStore.get(ROOT);
    const meta = await reqPromise(getReq);
    if (!meta) throw new StorageError('NO_META', '元数据缺失，仓库未初始化');
    metaStore.put({ ...meta, activeKid: newActiveKid, verifier: newVerifier });
    await txPromise(tx);
  }

  async putNote(note) {
    const tx = this._db.transaction('notes', 'readwrite');
    tx.objectStore('notes').put(note);
    await txPromise(tx);
  }

  async getNote(id) {
    const tx = this._db.transaction('notes', 'readonly');
    return reqPromise(tx.objectStore('notes').get(id));
  }

  async listNotes() {
    const tx = this._db.transaction('notes', 'readonly');
    return reqPromise(tx.objectStore('notes').getAll());
  }

  async deleteNote(id) {
    const tx = this._db.transaction('notes', 'readwrite');
    tx.objectStore('notes').delete(id);
    await txPromise(tx);
  }

  async countNotesByKid(kid) {
    const all = await this.listNotes();
    return all.reduce((n, note) => n + (note.envelope && note.envelope.kid === kid ? 1 : 0), 0);
  }

  // 返回 kid 不等于 activeKid 的笔记 id（按 updatedAt 倒序，先迁移最近的笔记）。
  async listStaleNoteIds(activeKid, afterId = null, limit = 50) {
    const all = await this.listNotes();
    const stale = all
      .filter((note) => note.envelope && note.envelope.kid !== activeKid)
      .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
      .map((note) => note.id);
    const start = afterId ? stale.indexOf(afterId) + 1 : 0;
    return stale.slice(start, start + limit);
  }

  async getMigrationState() {
    const tx = this._db.transaction('migration', 'readonly');
    return reqPromise(tx.objectStore('migration').get(ACTIVE));
  }

  async saveMigrationState(state) {
    const tx = this._db.transaction('migration', 'readwrite');
    tx.objectStore('migration').put({ ...state, id: ACTIVE });
    await txPromise(tx);
  }

  async clearMigrationState() {
    const tx = this._db.transaction('migration', 'readwrite');
    tx.objectStore('migration').delete(ACTIVE);
    await txPromise(tx);
  }

  async listFailures() {
    const tx = this._db.transaction('failures', 'readonly');
    return reqPromise(tx.objectStore('failures').getAll());
  }

  async saveFailure(failure) {
    const tx = this._db.transaction('failures', 'readwrite');
    tx.objectStore('failures').put(failure);
    await txPromise(tx);
  }

  async clearFailures() {
    const tx = this._db.transaction('failures', 'readwrite');
    tx.objectStore('failures').clear();
    await txPromise(tx);
  }
}
