// IndexedDB 存储层。
// 三个对象仓库：
//   notes: { id(自增), title, ciphertext, iv, keyVersion, updatedAt }
//   keys : { version, wrapped, iv, createdAt, status }
//   meta : { key, value }  —— kdf 参数 / currentKeyVersion / migration 检查点

const DB_NAME = 'secure-notes';
const DB_VERSION = 1;

function reqToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function txDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error('事务被中止'));
  });
}

export class NoteStore {
  constructor(dbName = DB_NAME) {
    this.dbName = dbName;
    this.db = null;
  }

  async open() {
    this.db = await new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('notes')) {
          db.createObjectStore('notes', { keyPath: 'id', autoIncrement: true });
        }
        if (!db.objectStoreNames.contains('keys')) {
          db.createObjectStore('keys', { keyPath: 'version' });
        }
        if (!db.objectStoreNames.contains('meta')) {
          db.createObjectStore('meta', { keyPath: 'key' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('数据库被其他页面占用，请关闭其他标签页'));
    });
    return this;
  }

  _store(name, mode = 'readonly') {
    return this.db.transaction(name, mode).objectStore(name);
  }

  // ---- meta ----
  async getMeta(key) {
    const row = await reqToPromise(this._store('meta').get(key));
    return row ? row.value : undefined;
  }

  async setMeta(key, value) {
    await reqToPromise(this._store('meta', 'readwrite').put({ key, value }));
  }

  async deleteMeta(key) {
    await reqToPromise(this._store('meta', 'readwrite').delete(key));
  }

  // ---- keys ----
  async getAllKeyRecords() {
    return reqToPromise(this._store('keys').getAll());
  }

  async putKeyRecord(rec) {
    await reqToPromise(this._store('keys', 'readwrite').put(rec));
  }

  async deleteKeyRecord(version) {
    await reqToPromise(this._store('keys', 'readwrite').delete(version));
  }

  // ---- notes ----
  async putNote(note) {
    const tx = this.db.transaction('notes', 'readwrite');
    const id = await reqToPromise(tx.store.put(note));
    await txDone(tx);
    return id;
  }

  async getNote(id) {
    return reqToPromise(this._store('notes').get(id));
  }

  async getAllNotes() {
    return reqToPromise(this._store('notes').getAll());
  }

  async deleteNote(id) {
    await reqToPromise(this._store('notes', 'readwrite').delete(id));
  }

  async countNotes() {
    return reqToPromise(this._store('notes').count());
  }

  // 游标分页：从 afterId（不含）之后取 limit 条，用于迁移断点续跑
  async iterateNotes(afterId, limit) {
    const range = IDBKeyRange.lowerBound(afterId ?? 0, true);
    return new Promise((resolve, reject) => {
      const notes = [];
      let lastId = afterId ?? 0;
      const req = this._store('notes').openCursor(range);
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor || notes.length >= limit) {
          resolve({ notes, lastId, done: !cursor });
          return;
        }
        notes.push(cursor.value);
        lastId = cursor.key;
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  // 单事务批量写入，保证“一批要么全落盘要么全不落”，配合检查点实现安全续跑
  async putNotesBatch(notes) {
    if (!notes.length) return;
    const tx = this.db.transaction('notes', 'readwrite');
    for (const n of notes) tx.store.put(n);
    await txDone(tx);
  }

  close() {
    this.db?.close();
    this.db = null;
  }
}
