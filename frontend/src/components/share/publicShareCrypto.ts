/** Minimal AES-GCM helpers for public share page (kept separate from main crypto bundle). */

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function arrayBufferToBase64(data: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    data instanceof ArrayBuffer
      ? new Uint8Array(data)
      : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export async function importFileKey(rawKeyBase64: string): Promise<CryptoKey> {
  const keyData = base64ToArrayBuffer(rawKeyBase64);
  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

export async function decryptSharedFile(encrypted: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    encrypted
  );
}

export type PublicShareKdf = {
  alg: 'pbkdf2-sha256';
  params: { iterations: number; hash: 'SHA-256' } | null;
  salt: string; // base64
  wrappedKey?: string; // base64
  wrappedKeyIv?: string; // base64
};

export async function derivePublicShareKeyPBKDF2(
  passphrase: string,
  saltB64: string,
  iterations: number
): Promise<CryptoKey> {
  const salt = new Uint8Array(base64ToArrayBuffer(saltB64));
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function unwrapFileKeyFromPublicShare(
  wrappedKeyB64: string,
  wrappedKeyIvB64: string,
  shareKey: CryptoKey
): Promise<CryptoKey> {
  const ct = base64ToArrayBuffer(wrappedKeyB64);
  const iv = new Uint8Array(base64ToArrayBuffer(wrappedKeyIvB64));
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, shareKey, ct);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

/** Check whether a filename string is in the encrypted JSON format. */
export function isEncryptedFilename(filename: string): boolean {
  if (!filename || filename[0] !== '{') return false;
  try {
    const parsed = JSON.parse(filename);
    return typeof parsed === 'object' && parsed !== null && 'c' in parsed && 'n' in parsed;
  } catch {
    return false;
  }
}

/** Decrypt an encrypted filename JSON string using an AES-GCM key. */
export async function decryptEncryptedFilename(encryptedJson: string, key: CryptoKey): Promise<string> {
  const { c, n } = JSON.parse(encryptedJson);
  const ciphertext = base64ToArrayBuffer(c);
  const iv = new Uint8Array(base64ToArrayBuffer(n));
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}
