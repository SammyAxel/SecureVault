/**
 * SecureVault Crypto Library
 * Handles all client-side encryption/decryption using Web Crypto API
 */

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

// Store keys in memory and localStorage (shared across tabs)
const KEYS_STORAGE_KEY = 'securevault_keys';
let currentKeys: KeyBundle | null = null;

export function setCurrentKeys(keys: KeyBundle): void {
  currentKeys = keys;
  // Also save to localStorage for persistence across tabs
  try {
    localStorage.setItem(KEYS_STORAGE_KEY, JSON.stringify(keys));
  } catch (e) {
    console.warn('Failed to save keys to localStorage:', e);
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
    console.warn('Failed to restore keys from localStorage:', e);
  }
  
  return null;
}

export function clearCurrentKeys(): void {
  currentKeys = null;
  try {
    localStorage.removeItem(KEYS_STORAGE_KEY);
  } catch (e) {
    console.warn('Failed to clear keys from localStorage:', e);
  }
}

/**
 * Calculate SHA256 hash of a file (for VirusTotal scanning)
 * Returns hex string
 */
export async function calculateFileHash(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}
