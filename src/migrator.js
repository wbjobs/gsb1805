// 可续迁移器：把旧 keyVersion 的笔记批量重加密到新版本。
// 断点续跑原理：
//   每批 = 一次 IDB 事务（要么全写要么不写）+ 随后持久化 migration 检查点(cursor)。
//   崩溃只会丢失“已写盘但检查点未更新”的那批 -> 重跑时对这些记录再加密一次，
//   AES-GCM 每次随机 IV，重复加密幂等安全。

export class Migrator {
  /**
   * @param {object} deps
   *  store        存储层（需实现 iterateNotes/putNotesBatch/setMeta）
   *  crypto       加密客户端（需实现 reencryptBatch）
   *  resolveDekId (version) => worker 内 DEK 句柄
   *  batchSize    每批条数
   *  onProgress   ({processed, cursor, done}) => void
   */
  constructor({ store, crypto, resolveDekId, batchSize = 100, onProgress }) {
    this.store = store;
    this.crypto = crypto;
    this.resolveDekId = resolveDekId;
    this.batchSize = batchSize;
    this.onProgress = onProgress || (() => {});
    this._aborted = false;
  }

  abort() {
    this._aborted = true;
  }

  /**
   * @param state {from, to, cursor, processed, failed[], done}
   * @returns {done: boolean, state} done=false 表示被中止，可再次 run(state) 续跑
   */
  async run(state) {
    let cursor = state.cursor ?? 0;
    while (!this._aborted) {
      const { notes, lastId, done } = await this.store.iterateNotes(cursor, this.batchSize);
      if (notes.length) {
        const updated = await this._reencryptNotes(notes, state);
        await this.store.putNotesBatch(updated); // 单事务落盘
      }
      cursor = lastId;
      state.cursor = cursor;
      state.processed += notes.length;
      await this.store.setMeta('migration', state); // 持久化检查点
      this.onProgress({ processed: state.processed, cursor, done, failed: state.failed.length });
      if (done) break;
      await new Promise((r) => setTimeout(r, 0)); // 让出主线程，保持 UI 响应
    }
    if (this._aborted) return { done: false, state };
    state.done = true;
    await this.store.setMeta('migration', state);
    return { done: true, state };
  }

  async _reencryptNotes(notes, state) {
    const targets = notes.filter((n) => n.keyVersion !== state.to);
    const skipped = notes.filter((n) => n.keyVersion === state.to);
    // 按源密钥版本分组（兼容历史上多次中断留下的混合版本）
    const groups = new Map();
    for (const n of targets) {
      if (!groups.has(n.keyVersion)) groups.set(n.keyVersion, []);
      groups.get(n.keyVersion).push(n);
    }
    const out = [...skipped];
    for (const [ver, group] of groups) {
      try {
        const re = await this.crypto.reencryptBatch({
          fromDekId: this.resolveDekId(ver),
          toDekId: this.resolveDekId(state.to),
          items: group.map((n) => ({ ciphertext: n.ciphertext, iv: n.iv })),
        });
        group.forEach((n, i) => {
          out.push({ ...n, ciphertext: re[i].ciphertext, iv: re[i].iv, keyVersion: state.to });
        });
      } catch (e) {
        // 整批失败时逐条隔离：坏数据记入 failed，其余继续，不阻塞整体迁移
        for (const n of group) {
          try {
            const [re] = await this.crypto.reencryptBatch({
              fromDekId: this.resolveDekId(ver),
              toDekId: this.resolveDekId(state.to),
              items: [{ ciphertext: n.ciphertext, iv: n.iv }],
            });
            out.push({ ...n, ciphertext: re.ciphertext, iv: re.iv, keyVersion: state.to });
          } catch {
            state.failed.push(n.id);
            out.push(n); // 保留原文与旧版本号，旧密钥因此不会被删除
          }
        }
      }
    }
    return out;
  }
}
