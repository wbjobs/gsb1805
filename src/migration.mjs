// 迁移器：把旧 DEK 版本的笔记分批重加密到活动 DEK。
//
// 断点续迁策略：
//   - 每批从存储里重新取“kid !== activeKid”的首页 N 条；本批成功的条目会换 kid，
//     下一批自然取到后续条目。中断后重跑只会重复处理“尚未换 kid”的条目，
//     重加密幂等安全（新 IV、明文不变），因此不需要记录庞大的已处理 id 列表。
//   - 断点状态（目标 kid、计数、状态机）每批结束落库，刷新/崩溃后可无缝续跑。
//   - 单条失败记入 failures，不阻塞其它条目；全部成功（无残留旧 kid）才算完成。

import { EventEmitter, yieldToEventLoop } from './events.mjs';
import { CryptoError, reencrypt } from './crypto-core.mjs';
import { KeyringError } from './keyring.mjs';

export const MIGRATION_STATUS = {
  RUNNING: 'running',
  PAUSED: 'paused',
  DONE: 'done',
};

export class MigrationError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'MigrationError';
    this.code = code;
    if (cause) this.cause = cause;
  }
}

export class Migrator extends EventEmitter {
  constructor(storage) {
    super();
    this._storage = storage;
    this._running = false;
    this._pauseRequested = false;
  }

  get running() {
    return this._running;
  }

  async getState() {
    return this._storage.getMigrationState();
  }

  pause() {
    this._pauseRequested = true;
  }

  async _persist(state) {
    await this._storage.saveMigrationState({ ...state, updatedAt: Date.now() });
  }

  // 启动或续跑迁移。opts.targetKid 用于新建迁移；续跑时从断点读取。
  async run(keyring, {
    batchSize = 25,
    batchDelayMs = 4,
    concurrency = 4,
    targetKid = null,
  } = {}) {
    if (this._running) throw new MigrationError('ALREADY_RUNNING', '迁移正在进行中');
    this._running = true;
    this._pauseRequested = false;

    // 本次运行中已经失败的条目不再重复尝试：防止“整批持续失败”导致零进展死循环。
    // 失败记录已持久化，用户修复后调用 retryFailures（清空 failures）即可重跑。
    const skipIds = new Set((await this._storage.listFailures()).map((f) => f.id));

    let state = await this._storage.getMigrationState();
    if (!state) {
      if (!targetKid) {
        this._running = false;
        throw new MigrationError('NO_TARGET', '缺少迁移目标密钥版本');
      }
      state = {
        targetKid,
        migratedCount: 0,
        failedCount: 0,
        status: MIGRATION_STATUS.RUNNING,
        startedAt: Date.now(),
      };
    } else {
      state = { ...state, status: MIGRATION_STATUS.RUNNING };
    }
    await this._persist(state);

    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (this._pauseRequested) {
          state.status = MIGRATION_STATUS.PAUSED;
          await this._persist(state);
          this.emit('paused', { state });
          return state;
        }

        const activeKid = keyring.activeKid;
        if (state.targetKid !== activeKid) {
          throw new MigrationError(
            'TARGET_MISMATCH',
            `迁移目标 ${state.targetKid} 与当前活动密钥 ${activeKid} 不一致，请重新轮换`,
          );
        }

        const ids = (await this._storage.listStaleNoteIds(activeKid, null, 1_000_000))
          .filter((id) => !skipIds.has(id))
          .slice(0, batchSize);
        if (ids.length === 0) break;

        let batchOk = 0;
        for (let i = 0; i < ids.length; i += concurrency) {
          const chunk = ids.slice(i, i + concurrency);
          const results = await Promise.allSettled(
            chunk.map((id) => this._migrateOne(keyring, activeKid, id)),
          );
          for (let j = 0; j < results.length; j += 1) {
            const result = results[j];
            if (result.status === 'fulfilled') {
              batchOk += 1;
            } else {
              skipIds.add(chunk[j]);
              await this._storage.saveFailure({
                id: chunk[j],
                error: result.reason?.message || String(result.reason),
                at: Date.now(),
              });
              this.emit('itemerror', { id: chunk[j], error: result.reason });
            }
          }
        }

        state.migratedCount += batchOk;
        state.failedCount = (await this._storage.listFailures()).length;
        const remaining = await this._storage.listStaleNoteIds(activeKid, null, 1_000_000);
        await this._persist(state);
        this.emit('progress', {
          migrated: batchOk,
          migratedTotal: state.migratedCount,
          remaining: remaining.length,
        });

        if (batchDelayMs > 0) await yieldToEventLoop(batchDelayMs);
      }

      // 终检：只要还有旧 kid 笔记（例如全是失败条目），就不宣布完成、不删除旧密钥。
      const leftover = await this._storage.listStaleNoteIds(state.targetKid, null, 1_000_000);
      if (leftover.length > 0) {
        state.status = MIGRATION_STATUS.PAUSED;
        await this._persist(state);
        this.emit('blocked', { remaining: leftover.length, state });
        return state;
      }

      for (const record of await this._storage.listKeys()) {
        if (record.id !== state.targetKid) await this._storage.deleteKey(record.id);
      }
      state.status = MIGRATION_STATUS.DONE;
      state.completedAt = Date.now();
      await this._persist(state);
      await this._storage.clearMigrationState();
      this.emit('done', { state });
      return state;
    } catch (err) {
      // 致命错误（存储不可用等）：保留断点，下次可续跑。
      state.status = MIGRATION_STATUS.PAUSED;
      await safePersist(this._storage, state);
      this.emit('error', err);
      throw err;
    } finally {
      this._running = false;
      this._pauseRequested = false;
    }
  }

  async _migrateOne(keyring, targetKid, id) {
    const note = await this._storage.getNote(id);
    if (!note || !note.envelope || note.envelope.kid === targetKid) return; // 已被其它运行者迁过
    const oldDek = keyring.getDek(note.envelope.kid); // 旧密钥已删除时抛 UNKNOWN_KID
    const envelope = await reencryptSafe(oldDek, keyring.activeDek, note.envelope, targetKid);
    await this._storage.putNote({ ...note, envelope, updatedAt: Date.now() });
  }
}

async function safePersist(storage, state) {
  try { await storage.saveMigrationState({ ...state, updatedAt: Date.now() }); } catch { /* ignore */ }
}

async function reencryptSafe(oldDek, newDek, envelope, targetKid) {
  return reencrypt(oldDek, newDek, envelope, targetKid);
}

export function isRetriableCryptoError(err) {
  return err instanceof CryptoError || err instanceof KeyringError;
}
