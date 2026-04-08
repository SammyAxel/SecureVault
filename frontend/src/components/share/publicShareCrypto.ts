/** Minimal AES-GCM helpers for public share page (kept separate from main crypto bundle). */

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
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
