// 密钥管理器：负责初始化、解锁、轮换，并编排迁移。
// 通过 onEvent 向外抛出事件（progress / migration-* / error），UI 层据此提示。
import { CryptoError, randomBytes, SALT_LEN, KDF_ITERATIONS } from './crypto-core.js';
import { Migrator } from './migrator.js';

export class KeyManager {
  /**
   * @param deps { store, crypto, batchSize?, onEvent? }
   *  onEvent({type, ...}) type ∈
   *    migration-start | migration-progress | migration-done | migration-paused | migration-error
   */
  constructor({ store, crypto, batchSize = 100, onEvent }) {
    this.store = store;
    this.crypto = crypto;
    this.batchSize = batchSize;
    this.emit = onEvent || (() => {});
    this.kekId = null;
    this.deks = new Map(); // version -> worker keyId
    this.currentVersion = 0;
    this._migrator = null;
  }

  get unlocked() {
    return this.kekId !== null;
  }

  get migrating() {
    return !!this._migrator;
  }

  async isInitialized() {
    return !!(await this.store.getMeta('kdf'));
  }

  // 首次使用：生成盐、派生 KEK、生成 v1 DEK 并包裹落盘
  async setup(password) {
    if (await this.isInitialized()) {
      throw new CryptoError('ALREADY_INITIALIZED', '已初始化，请直接解锁');
    }
    const salt = randomBytes(SALT_LEN);
    const kekId = await this.crypto.deriveKEK({ password, salt, iterations: KDF_ITERATIONS });
    const dekId = await this.crypto.generateDEK();
    const { wrapped, iv } = await this.crypto.wrapDEK({ dekId, kekId });
    await this.store.putKeyRecord({ version: 1, wrapped, iv, createdAt: Date.now(), status: 'active' });
    await this.store.setMeta('kdf', { salt, iterations: KDF_ITERATIONS });
    await this.store.setMeta('currentKeyVersion', 1);
    this.kekId = kekId;
    this.deks = new Map([[1, dekId]]);
    this.currentVersion = 1;
  }

  // 解锁：派生 KEK -> 解包全部 DEK -> 若有未完成迁移则自动续跑
  async unlock(password) {
    const kdf = await this.store.getMeta('kdf');
    if (!kdf) throw new CryptoError('NOT_INITIALIZED', '尚未初始化，请先设置口令');
    const kekId = await this.crypto.deriveKEK({
      password, salt: kdf.salt, iterations: kdf.iterations,
    });
    const records = await this.store.getAllKeyRecords();
    const deks = new Map();
    for (const rec of records) {
      // 任一解包失败（典型原因：口令错误）整体失败，不进入半解锁状态
      deks.set(rec.version, await this.crypto.unwrapDEK({
        wrapped: rec.wrapped, iv: rec.iv, kekId,
      }));
    }
    this.kekId = kekId;
    this.deks = deks;
    this.currentVersion = await this.store.getMeta('currentKeyVersion');
    const mig = await this.store.getMeta('migration');
    if (mig && !mig.done) this._runMigration(mig); // 后台续跑，不阻塞解锁
  }

  async lock() {
    await this.crypto.releaseAll();
    this.kekId = null;
    this.deks.clear();
    this.currentVersion = 0;
  }

  _requireUnlocked() {
    if (!this.unlocked) throw new CryptoError('LOCKED', '尚未解锁，请先输入口令');
  }

  // 加密新笔记：始终使用当前版本密钥
  async encryptNote(plaintext) {
    this._requireUnlocked();
    const { ciphertext, iv } = await this.crypto.encrypt({
      dekId: this.deks.get(this.currentVersion), plaintext,
    });
    return { ciphertext, iv, keyVersion: this.currentVersion };
  }

  // 解密笔记：按记录上的 keyVersion 选钥，旧数据在迁移完成前/后都可解
  async decryptNote(note) {
    this._requireUnlocked();
    const dekId = this.deks.get(note.keyVersion);
    if (!dekId) {
      throw new CryptoError('KEY_VERSION_MISSING', `缺少 v${note.keyVersion} 版本密钥，无法解密`);
    }
    return this.crypto.decrypt({ dekId, ciphertext: note.ciphertext, iv: note.iv });
  }

  /**
   * 轮换密钥（可选同时更换口令）。
   * 流程：生成新 DEK -> （换口令则重包裹所有存量密钥）-> 新 DEK 落盘 ->
   *       写入迁移检查点 -> 切换 currentKeyVersion（新笔记立即用新密钥）-> 后台迁移旧数据。
   */
  async rotate({ newPassword } = {}) {
    this._requireUnlocked();
    if (this._migrator) throw new CryptoError('MIGRATION_RUNNING', '已有迁移在进行中，请稍候');

    const oldVersion = this.currentVersion;
    const newVersion = oldVersion + 1;

    // 1. 可选：更换口令 -> 新 KEK，重包裹所有存量 DEK（旧 DEK 在迁移完成前必须保留）
    if (newPassword) {
      const salt = randomBytes(SALT_LEN);
      const newKekId = await this.crypto.deriveKEK({
        password: newPassword, salt, iterations: KDF_ITERATIONS,
      });
      const records = await this.store.getAllKeyRecords();
      for (const rec of records) {
        const { wrapped, iv } = await this.crypto.wrapDEK({
          dekId: this.deks.get(rec.version), kekId: newKekId,
        });
        await this.store.putKeyRecord({ ...rec, wrapped, iv });
      }
      await this.store.setMeta('kdf', { salt, iterations: KDF_ITERATIONS });
      await this.crypto.release(this.kekId);
      this.kekId = newKekId;
    }

    // 2. 新 DEK 落盘
    const newDekId = await this.crypto.generateDEK();
    const { wrapped, iv } = await this.crypto.wrapDEK({ dekId: newDekId, kekId: this.kekId });
    await this.store.putKeyRecord({
      version: newVersion, wrapped, iv, createdAt: Date.now(), status: 'active',
    });
    this.deks.set(newVersion, newDekId);

    // 3. 先写检查点再切换当前版本：任何时刻崩溃都能续跑
    const mig = {
      from: oldVersion, to: newVersion,
      cursor: 0, processed: 0, failed: [], done: false, startedAt: Date.now(),
    };
    await this.store.setMeta('migration', mig);
    await this.store.setMeta('currentKeyVersion', newVersion);
    this.currentVersion = newVersion;

    await this._runMigration(mig);
    return newVersion;
  }

  pauseMigration() {
    this._migrator?.abort();
  }

  async _runMigration(mig) {
    const migrator = new Migrator({
      store: this.store,
      crypto: this.crypto,
      resolveDekId: (v) => this.deks.get(v),
      batchSize: this.batchSize,
      onProgress: (p) => this.emit({ type: 'migration-progress', ...p }),
    });
    this._migrator = migrator;
    this.emit({ type: 'migration-start', from: mig.from, to: mig.to });
    try {
      const { done, state } = await migrator.run(mig);
      if (!done) {
        this.emit({ type: 'migration-paused', processed: state.processed });
        return;
      }
      if (state.failed.length === 0) {
        // 全部迁移成功：旧 DEK 已无引用，安全删除
        await this.store.deleteKeyRecord(state.from);
        const oldDekId = this.deks.get(state.from);
        this.deks.delete(state.from);
        if (oldDekId) await this.crypto.release(oldDekId);
        await this.store.deleteMeta('migration');
        this.emit({ type: 'migration-done', from: state.from, to: state.to, processed: state.processed });
      } else {
        // 有坏数据：保留旧密钥与检查点，提示用户处理后可再次触发续跑
        await this.store.setMeta('migration', { ...state, done: false });
        this.emit({ type: 'migration-error', failed: state.failed });
      }
    } catch (err) {
      this.emit({ type: 'migration-error', error: err });
    } finally {
      this._migrator = null;
    }
  }
}
