// Keyring：管理密钥版本、解锁、密码轮换（旧 DEK 用新 KEK 重新包装）。
//
// 关键不变量：
//   1. 每个 KeyVersion 记录里的 {salt, iterations} 对应当前包装其 wrappedDek 的 KEK；
//      轮换后所有记录都被新 KEK 重新包装，因此 salt/iterations 会一并更新为新值。
//   2. 密码轮换会生成新 DEK（新笔记用新密钥）；旧 DEK 保留，直到全部笔记迁移完毕。
//   3. 解锁后内存中持有全部 DEK（CryptoKey, non-persistent），关闭/刷新即清零。

import {
  CryptoError,
  deriveKek,
  generateDek,
  wrapDek,
  unwrapDek,
  encrypt,
  decrypt,
  makeKeyVersion,
  newKeyId,
  randomBytes,
  PBKDF2_ITERATIONS,
} from './crypto-core.mjs';

const VERIFIER_TEXT = 'vault-verifier-v1';

export class KeyringError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'KeyringError';
    this.code = code;
    if (cause) this.cause = cause;
  }
}

export class Keyring {
  constructor(storage, { versions, activeKid, kek, deks, verifier }) {
    this._storage = storage;
    this._versions = new Map(versions.map((v) => [v.id, v]));
    this._activeKid = activeKid;
    this._kek = kek;
    this._deks = deks; // Map<kid, CryptoKey>
    this._verifier = verifier;
  }

  get activeKid() {
    return this._activeKid;
  }

  get activeDek() {
    const dek = this._deks.get(this._activeKid);
    if (!dek) throw new KeyringError('NO_ACTIVE_DEK', '活动数据密钥缺失');
    return dek;
  }

  getDek(kid) {
    const dek = this._deks.get(kid);
    if (!dek) throw new KeyringError('UNKNOWN_KID', `未知的密钥版本: ${kid}`);
    return dek;
  }

  getKeyVersion(kid) {
    const v = this._versions.get(kid);
    if (!v) throw new KeyringError('UNKNOWN_KID', `未知的密钥版本: ${kid}`);
    return v;
  }

  // 校验当前主密码：用活动版本的 KDF 参数重新派生 KEK 并尝试解封活动 DEK。
  async checkPassword(password) {
    const record = this._versions.get(this._activeKid);
    const candidate = await deriveKek(password, { salt: record.salt, iterations: record.iterations });
    try {
      await unwrapDek(record.wrappedDek, candidate);
      return true;
    } catch (err) {
      throw mapUnlockError(err);
    }
  }

  static async initialize(storage, password, { iterations = PBKDF2_ITERATIONS, now = Date.now } = {}) {
    const existing = await storage.getMeta();
    if (existing && existing.initialized) {
      throw new KeyringError('ALREADY_INITIALIZED', '仓库已初始化，请勿重复初始化');
    }
    const salt = randomBytes(16);
    const kek = await deriveKek(password, { salt, iterations });
    const dek = await generateDek();
    const wrappedDek = await wrapDek(dek, kek);
    const id = newKeyId();
    const version = makeKeyVersion({ id, salt, iterations, wrappedDek, createdAt: now() });
    const verifier = await encrypt(dek, VERIFIER_TEXT, id);
    await storage.saveKey(version);
    await storage.saveMeta({
      initialized: true,
      activeKid: id,
      verifier,
      createdAt: now(),
    });
    return new Keyring(storage, {
      versions: [version],
      activeKid: id,
      kek,
      deks: new Map([[id, dek]]),
      verifier,
    });
  }

  static async unlock(storage, password) {
    const meta = await storage.getMeta();
    if (!meta || !meta.initialized) {
      throw new KeyringError('NOT_INITIALIZED', '仓库尚未初始化');
    }
    const versions = await storage.listKeys();
    if (versions.length === 0) {
      throw new KeyringError('NO_KEY_VERSIONS', '密钥版本记录缺失，数据可能已被清除');
    }
    const activeRecord = versions.find((v) => v.id === meta.activeKid) || versions[versions.length - 1];

    // 用当前密码 + 活动版本的 KDF 参数派生 KEK。密码错误会在 AES-KW 解封时抛出。
    let kek;
    try {
      kek = await deriveKek(password, { salt: activeRecord.salt, iterations: activeRecord.iterations });
    } catch (err) {
      throw mapUnlockError(err);
    }

    const deks = new Map();
    for (const record of versions) {
      try {
        deks.set(record.id, await unwrapDek(record.wrappedDek, kek));
      } catch (err) {
        throw mapUnlockError(err);
      }
    }

    // 二级校验：解封成功后再解密 verifier，防止密钥/数据不一致被静默忽略。
    const activeDek = deks.get(meta.activeKid);
    try {
      const text = await decrypt(activeDek, meta.verifier);
      if (text !== VERIFIER_TEXT) throw new Error('verifier mismatch');
    } catch (err) {
      if (err instanceof CryptoError && err.code === 'UNWRAP_FAILED') throw mapUnlockError(err);
      throw new KeyringError('VERIFY_FAILED', '身份校验失败：密码错误或密钥记录已损坏', err);
    }

    return new Keyring(storage, {
      versions,
      activeKid: meta.activeKid,
      kek,
      deks,
      verifier: meta.verifier,
    });
  }

  // 轮换主密码：新 KEK + 新 DEK，旧 DEK 全部由新 KEK 重新包装（单事务原子提交）。
  // 返回 { newKid }。调用方随后应启动/续跑迁移，把旧笔记重加密到新 DEK。
  async rotate(currentPassword, newPassword, { iterations = PBKDF2_ITERATIONS, now = Date.now } = {}) {
    if (currentPassword !== undefined) {
      await this.checkPassword(currentPassword);
    }
    if (typeof newPassword !== 'string' || newPassword.length === 0) {
      throw new KeyringError('BAD_PASSWORD', '新密码不能为空');
    }
    const salt = randomBytes(16);
    const newKek = await deriveKek(newPassword, { salt, iterations });

    const newDek = await generateDek();
    const newId = newKeyId();
    const newVersion = makeKeyVersion({
      id: newId,
      salt,
      iterations,
      wrappedDek: await wrapDek(newDek, newKek),
      createdAt: now(),
    });

    // 旧 DEK 用新 KEK 重新包装；salt/iterations 更新为新 KEK 的派生参数。
    const rewrapped = [];
    for (const [kid, dek] of this._deks) {
      if (kid === newId) continue;
      rewrapped.push(makeKeyVersion({
        ...this._versions.get(kid),
        salt,
        iterations,
        wrappedDek: await wrapDek(dek, newKek),
      }));
    }

    const newVerifier = await encrypt(newDek, VERIFIER_TEXT, newId);
    await this._storage.commitRotation({
      newVersion,
      rewrapped,
      newActiveKid: newId,
      newVerifier,
    });

    this._versions.set(newId, newVersion);
    for (const record of rewrapped) this._versions.set(record.id, record);
    this._deks.set(newId, newDek);
    this._kek = newKek;
    this._activeKid = newId;
    this._verifier = newVerifier;
    return { newKid: newId };
  }
}

function mapUnlockError(err) {
  if (err instanceof KeyringError) return err;
  if (err instanceof CryptoError && (err.code === 'UNWRAP_FAILED' || err.code === 'DECRYPT_FAILED')) {
    return new KeyringError('BAD_PASSWORD', '密码错误，或加密数据已损坏', err);
  }
  if (err instanceof CryptoError && err.code === 'KDF_FAILED') {
    return new KeyringError('KDF_FAILED', '密钥派生失败', err);
  }
  return new KeyringError('UNLOCK_FAILED', '解锁失败', err);
}
