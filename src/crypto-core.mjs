// 加密原语：所有密码学操作都基于 Web Crypto (SubtleCrypto)。
//
// 密钥层级：
//   password --PBKDF2--> KEK(主密钥, CryptoKey, non-extractable)
//   DEK(数据密钥, CryptoKey, extractable) --AES-KW(KEK)--> wrappedDek(Uint8Array, 落库)
//
// 数据格式（envelope）：
//   每条密文是 { v:1, kid, iv, ct } 组成的二进制数组（StructuredClone 可序列化）。
//
// 说明：KEK 只用于 wrap/unwrap DEK；DEK 用于加解密笔记。轮换密码时无需重加密全部
// 数据，只需用新 KEK 重新包装同一把 DEK；跨 DEK 版本迁移（本项目轮换会生成新 DEK）
// 由迁移器在后台分批完成。

export const ENVELOPE_VERSION = 1;
export const PBKDF2_ITERATIONS = 310_000; // OWASP 2023+ 推荐量级（SHA-256）
export const KEY_BYTES = 32; // AES-256
export const IV_BYTES = 12; // GCM 推荐 96bit

export class CryptoError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
    if (cause) this.cause = cause;
  }
}

export function getSubtle() {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) {
    throw new CryptoError('NO_WEBCRYPTO', '当前环境不支持 Web Crypto API（需要 secure context）');
  }
  return subtle;
}

export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

// PBKDF2 派生 KEK。salt 与 iterations 随密钥版本记录落库，旧版本保留旧参数。
export async function deriveKek(password, { salt, iterations = PBKDF2_ITERATIONS }) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new CryptoError('BAD_PASSWORD', '密码不能为空');
  }
  const subtle = getSubtle();
  let baseKey;
  try {
    baseKey = await subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    return await subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-KW', length: 256 },
      false,
      ['wrapKey', 'unwrapKey'],
    );
  } catch (err) {
    if (err instanceof CryptoError) throw err;
    throw new CryptoError('KDF_FAILED', '密钥派生失败', err);
  }
}

// 生成一把随机的 AES-GCM-256 数据密钥（extractable，以便被 KEK 包装 / 迁移）。
export async function generateDek() {
  return getSubtle().generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

export async function wrapDek(dek, kek) {
  const subtle = getSubtle();
  try {
    const buf = await subtle.wrapKey('raw', dek, kek, 'AES-KW');
    return new Uint8Array(buf);
  } catch (err) {
    throw new CryptoError('WRAP_FAILED', '密钥包装失败', err);
  }
}

export async function unwrapDek(wrappedDek, kek) {
  const subtle = getSubtle();
  try {
    return await subtle.unwrapKey(
      'raw',
      wrappedDek instanceof Uint8Array ? wrappedDek : new Uint8Array(wrappedDek),
      kek,
      'AES-KW',
      { name: 'AES-GCM' },
      true,
      ['encrypt', 'decrypt'],
    );
  } catch (err) {
    // AES-KW 校验失败 / GCM tag 失败都会走这里：密码错误或数据损坏
    throw new CryptoError('UNWRAP_FAILED', '密钥解封失败（密码错误或数据已损坏）', err);
  }
}

// 加密明文 -> envelope（kid 由调用方提供，标识使用的 DEK 版本）。
export async function encrypt(dek, plaintext, kid) {
  const subtle = getSubtle();
  const iv = randomBytes(IV_BYTES);
  let ct;
  try {
    ct = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      dek,
      new TextEncoder().encode(plaintext),
    );
  } catch (err) {
    throw new CryptoError('ENCRYPT_FAILED', '加密失败', err);
  }
  return { v: ENVELOPE_VERSION, kid, iv, ct: new Uint8Array(ct) };
}

export async function decrypt(dek, envelope) {
  if (!envelope || envelope.v !== ENVELOPE_VERSION) {
    throw new CryptoError('BAD_ENVELOPE', `不支持的密文格式版本: ${envelope && envelope.v}`);
  }
  const subtle = getSubtle();
  try {
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: envelope.iv },
      dek,
      envelope.ct,
    );
    return new TextDecoder().decode(plain);
  } catch (err) {
    throw new CryptoError('DECRYPT_FAILED', '解密失败（密钥不匹配或数据已损坏）', err);
  }
}

// 用新 DEK 重加密一个 envelope，迁移期间逐条调用。
export async function reencrypt(oldDek, newDek, envelope, newKid) {
  const plaintext = await decrypt(oldDek, envelope);
  return encrypt(newDek, plaintext, newKid);
}

// 生成可落库 / 可 StructuredClone 的密钥版本记录。
export function makeKeyVersion({ id, salt, iterations, wrappedDek, createdAt = Date.now() }) {
  return { id, salt, iterations, wrappedDek, createdAt };
}

export function newKeyId() {
  // kid：时间戳 + 随机后缀，排序天然近似时间序
  const rand = randomBytes(6).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
  return `kv_${Date.now().toString(36)}_${rand}`;
}
