/**
 * SecureVault Crypto Library
 * Handles all client-side encryption/decryption using Web Crypto API
 */

import { logger } from './logger';
import { assertSubtleCrypto } from './webCryptoSupport';

// ============ KEY GENERATION ============

/**
 * Generate ECDSA keypair for authentication (signing)
 */
export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

/**
 * Generate RSA-OAEP keypair for encryption (key wrapping)
 */
export async function generateEncryptionKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate AES-GCM key for file encryption
 */
export async function generateFileKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ============ KEY EXPORT/IMPORT ============

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', key);
  return arrayBufferToBase64(exported);
}

export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('pkcs8', key);
  return arrayBufferToBase64(exported);
}

export async function importSigningPublicKey(pem: string): Promise<CryptoKey> {
  const binaryDer = base64ToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'spki',
    binaryDer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

export async function importSigningPrivateKey(pem: string): Promise<CryptoKey> {
  const binaryDer = base64ToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
}

export async function importEncryptionPublicKey(pem: string): Promise<CryptoKey> {
  const binaryDer = base64ToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'spki',
    binaryDer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

export async function importEncryptionPrivateKey(pem: string): Promise<CryptoKey> {
  const binaryDer = base64ToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

// ============ SIGNING ============

export async function signChallenge(privateKey: CryptoKey, challenge: string): Promise<string> {
  const data = new TextEncoder().encode(challenge);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );
  return arrayBufferToBase64(signature);
}

// ============ FILE ENCRYPTION ============

export async function encryptFile(file: ArrayBuffer): Promise<{
  encrypted: ArrayBuffer;
  key: CryptoKey;
  iv: Uint8Array;
}> {
  const key = await generateFileKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    file
  );
  
  return { encrypted, key, iv };
}

export async function decryptFile(
  encrypted: ArrayBuffer,
  key: CryptoKey,
  iv: Uint8Array
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    encrypted
  );
}

// ============ FILENAME ENCRYPTION (AES-GCM, per-file key) ============

/**
 * Encrypt a filename using the file's AES-GCM key.
 * Returns a JSON string: {"c":"<base64 ciphertext>","n":"<base64 iv>"}
 */
export async function encryptFilename(name: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(name);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return JSON.stringify({ c: arrayBufferToBase64(ciphertext), n: arrayBufferToBase64(iv) });
}

/**
 * Decrypt an encrypted filename JSON string using the file's AES-GCM key.
 */
export async function decryptFilename(encryptedJson: string, key: CryptoKey): Promise<string> {
  const { c, n } = JSON.parse(encryptedJson);
  const ciphertext = base64ToArrayBuffer(c);
  const iv = base64ToUint8Array(n);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

/**
 * Check whether a filename string is in the encrypted JSON format.
 */
export function isEncryptedFilename(filename: string): boolean {
  if (!filename || filename[0] !== '{') return false;
  try {
    const parsed = JSON.parse(filename);
    return typeof parsed === 'object' && parsed !== null && 'c' in parsed && 'n' in parsed;
  } catch {
    return false;
  }
}

// ============ KEY WRAPPING ============

export async function wrapKey(fileKey: CryptoKey, publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('raw', fileKey);
  const wrapped = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    exported
  );
  return arrayBufferToBase64(wrapped);
}

export async function unwrapKey(wrappedKey: string, privateKey: CryptoKey): Promise<CryptoKey> {
  const wrapped = base64ToArrayBuffer(wrappedKey);
  const unwrapped = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    wrapped
  );
  
  return crypto.subtle.importKey(
    'raw',
    unwrapped,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ============ PASSPHRASE PUBLIC SHARE (PBKDF2 -> AES-GCM) ============

export type PublicShareKdfParams = {
  iterations: number;
  hash: 'SHA-256';
};

export async function derivePublicShareKeyPBKDF2(
  passphrase: string,
  saltB64: string,
  params: PublicShareKdfParams
): Promise<CryptoKey> {
  assertSubtleCrypto();
  const salt = base64ToUint8Array(saltB64);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as unknown as BufferSource, iterations: params.iterations, hash: params.hash },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function generatePublicShareSaltB64(bytes: number = 16): string {
  const salt = crypto.getRandomValues(new Uint8Array(bytes));
  return arrayBufferToBase64(salt);
}

export async function wrapFileKeyForPublicShare(
  fileKey: CryptoKey,
  shareKey: CryptoKey
): Promise<{ wrappedKey: string; wrappedKeyIv: string }> {
  assertSubtleCrypto();
  const raw = await crypto.subtle.exportKey('raw', fileKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, shareKey, raw);
  return { wrappedKey: arrayBufferToBase64(ct), wrappedKeyIv: arrayBufferToBase64(iv) };
}

export async function unwrapFileKeyFromPublicShare(
  wrappedKeyB64: string,
  wrappedKeyIvB64: string,
  shareKey: CryptoKey
): Promise<CryptoKey> {
  assertSubtleCrypto();
  const ct = base64ToArrayBuffer(wrappedKeyB64);
  const iv = base64ToUint8Array(wrappedKeyIvB64);
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, shareKey, ct);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// ============ UTILITIES ============

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

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

// ============ DEVICE-LINK KEY TRANSFER (AES-GCM, end-to-end) ============

/**
 * Encrypt a KeyBundle for device-link transfer. The `transferKey` lives only in
 * the QR URL fragment (never sent to the server), so the server sees only ciphertext.
 * Returns { transferKey (base64url), encryptedKeys (base64), iv (base64) }.
 */
export async function encryptKeyBundleForTransfer(
  bundle: KeyBundle
): Promise<{ transferKey: string; encryptedKeys: string; iv: string }> {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const aesKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
  const plaintext = new TextEncoder().encode(JSON.stringify(bundle));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);

  return {
    transferKey: uint8ToBase64Url(rawKey),
    encryptedKeys: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
  };
}

/**
 * Decrypt a KeyBundle that was encrypted with `encryptKeyBundleForTransfer`.
 */
export async function decryptKeyBundleFromTransfer(
  transferKeyB64Url: string,
  encryptedKeysB64: string,
  ivB64: string
): Promise<KeyBundle> {
  const rawKey = base64UrlToUint8(transferKeyB64Url);
  const iv = base64ToUint8Array(ivB64);
  const ciphertext = base64ToArrayBuffer(encryptedKeysB64);

  const aesKey = await crypto.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, aesKey, ciphertext);

  const bundle = JSON.parse(new TextDecoder().decode(plaintext));
  if (!bundle?.signingPrivateKey || !bundle?.encryptionPrivateKey) {
    throw new Error('Decrypted key bundle is invalid');
  }
  return bundle as KeyBundle;
}

function uint8ToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToUint8(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ============ KEY STORAGE ============

// Key bundle (stored in keys file)
export interface KeyBundle {
  signingPublicKey: string;
  signingPrivateKey: string;
  encryptionPublicKey: string;
  encryptionPrivateKey: string;
}

export async function generateKeyBundle(): Promise<KeyBundle> {
  const [signingKeyPair, encryptionKeyPair] = await Promise.all([
    generateSigningKeyPair(),
    generateEncryptionKeyPair(),
  ]);
  
  return {
    signingPublicKey: await exportPublicKey(signingKeyPair.publicKey),
    signingPrivateKey: await exportPrivateKey(signingKeyPair.privateKey),
    encryptionPublicKey: await exportPublicKey(encryptionKeyPair.publicKey),
    encryptionPrivateKey: await exportPrivateKey(encryptionKeyPair.privateKey),
  };
}

/**
 * Check if a key bundle has the old password-encrypted format (no longer supported)
 */
export function isLegacyEncryptedKeyBundle(bundle: any): boolean {
  return bundle && bundle.version === 2 && bundle.encryptedSigningKey;
}

export function downloadKeyBundle(bundle: KeyBundle, username: string): void {
  const data = JSON.stringify(bundle, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = `${username}_keys.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function loadKeyBundleFromFile(file: File): Promise<KeyBundle> {
  const text = await file.text();
  const bundle = JSON.parse(text);
  if (isLegacyEncryptedKeyBundle(bundle)) {
    throw new Error('Password-protected key files are no longer supported. Please re-register to get a new key file.');
  }
  if (!bundle?.signingPrivateKey || !bundle?.encryptionPrivateKey) {
    throw new Error('Invalid key file format');
  }
  return bundle as KeyBundle;
}

// Private key material: kept in memory and localStorage for multi-tab use. Any XSS in this origin
// can read localStorage; keep dependencies trusted and avoid injecting third-party script.
const KEYS_STORAGE_KEY = 'securevault_keys';
let currentKeys: KeyBundle | null = null;

export function setCurrentKeys(keys: KeyBundle): void {
  currentKeys = keys;
  // Also save to localStorage for persistence across tabs
  try {
    localStorage.setItem(KEYS_STORAGE_KEY, JSON.stringify(keys));
  } catch (e) {
    logger.warn('Failed to save keys to localStorage:', e);
  }
}

export function getCurrentKeys(): KeyBundle | null {
  if (currentKeys) return currentKeys;
  
  // Try to restore from localStorage
  try {
    const stored = localStorage.getItem(KEYS_STORAGE_KEY);
    if (stored) {
      currentKeys = JSON.parse(stored) as KeyBundle;
      return currentKeys;
    }
  } catch (e) {
    logger.warn('Failed to restore keys from localStorage:', e);
  }
  
  return null;
}

export function clearCurrentKeys(): void {
  currentKeys = null;
  try {
    localStorage.removeItem(KEYS_STORAGE_KEY);
  } catch (e) {
    logger.warn('Failed to clear keys from localStorage:', e);
  }
}

/**
 * Calculate SHA256 hash of a file (for VirusTotal scanning)
 * Returns hex string
 */
export async function calculateFileHash(buffer: ArrayBuffer): Promise<string> {
  assertSubtleCrypto();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}
