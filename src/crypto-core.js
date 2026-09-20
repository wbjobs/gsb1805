// 纯加密核心：不依赖 DOM / Worker / IndexedDB，浏览器与 Node(>=20) 均可运行。
// 密钥层级：
//   用户口令 --PBKDF2(SHA-256, 60w 次)--> KEK(AES-GCM 256, 仅用于包裹/解包)
//   DEK(随机 AES-GCM 256, 按版本管理) --被 KEK 包裹后落盘--> keys 表
//   笔记正文 --DEK AES-GCM 加密--> notes 表(带 keyVersion)

const subtle = globalThis.crypto.subtle;

export const KDF_ITERATIONS = 600_000; // OWASP 对 PBKDF2-SHA256 的推荐量级
export const SALT_LEN = 16;
export const IV_LEN = 12; // AES-GCM 标准 96 位随机 IV

export class CryptoError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
    this.cause = cause;
  }
}

export function randomBytes(len) {
  const b = new Uint8Array(len);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function toU8(buf) {
  return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
}

export function bytesToB64(bytes) {
  const u8 = toU8(bytes);
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64');
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) {
    s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function b64ToBytes(b64) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

// 口令 -> KEK（不可导出，只能 wrap/unwrap）
export async function deriveKEK(password, salt, iterations = KDF_ITERATIONS) {
  const base = await subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return subtle.deriveKey(
    { name: 'PBKDF2', salt: toU8(salt), iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

// 生成新版本 DEK（可导出仅用于被 KEK 包裹落盘）
export async function generateDEK() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function wrapDEK(dek, kek) {
  const iv = randomBytes(IV_LEN);
  const wrapped = await subtle.wrapKey('raw', dek, kek, { name: 'AES-GCM', iv });
  return { wrapped: new Uint8Array(wrapped), iv };
}

export async function unwrapDEK(wrapped, iv, kek) {
  try {
    return await subtle.unwrapKey(
      'raw', toU8(wrapped), kek, { name: 'AES-GCM', iv: toU8(iv) },
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
  } catch (e) {
    throw new CryptoError('UNWRAP_FAILED', '密钥解包失败：口令错误或密钥数据已损坏', e);
  }
}

export async function encryptText(dek, plaintext) {
  const iv = randomBytes(IV_LEN);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv }, dek, new TextEncoder().encode(plaintext)
  );
  return { ciphertext: new Uint8Array(ct), iv };
}

export async function decryptText(dek, ciphertext, iv) {
  try {
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: toU8(iv) }, dek, toU8(ciphertext)
    );
    return new TextDecoder().decode(pt);
  } catch (e) {
    throw new CryptoError('DECRYPT_FAILED', '解密失败：数据已损坏或密钥不匹配', e);
  }
}
