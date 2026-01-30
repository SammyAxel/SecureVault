/**
 * SecureVault Crypto Library
 * Handles all client-side encryption/decryption using Web Crypto API
 */

// ============ PASSWORD-BASED KEY DERIVATION ============

/**
 * Derive an AES key from password using PBKDF2
 * This is used to encrypt the private keys before storage
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const passwordBuffer = new TextEncoder().encode(password);
  
  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  
  // Derive AES key using PBKDF2
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 600000, // High iteration count for security (OWASP recommendation)
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt private keys with password-derived key
 */
export async function encryptPrivateKeysWithPassword(
  signingPrivateKey: string,
  encryptionPrivateKey: string,
  password: string
): Promise<{
  encryptedSigningKey: string;
  encryptedEncryptionKey: string;
  salt: string;
  iv: string;
}> {
  // Generate random salt and IV
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Derive key from password
  const derivedKey = await deriveKeyFromPassword(password, salt);
  
  // Encrypt signing private key
  const signingKeyData = new TextEncoder().encode(signingPrivateKey);
  const encryptedSigning = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    derivedKey,
    signingKeyData
  );
  
  // Encrypt encryption private key (use same key but new IV for each)
  const iv2 = crypto.getRandomValues(new Uint8Array(12));
  const encryptionKeyData = new TextEncoder().encode(encryptionPrivateKey);
  const encryptedEncryption = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv2 },
    derivedKey,
    encryptionKeyData
  );
  
  return {
    encryptedSigningKey: arrayBufferToBase64(encryptedSigning) + ':' + arrayBufferToBase64(iv),
    encryptedEncryptionKey: arrayBufferToBase64(encryptedEncryption) + ':' + arrayBufferToBase64(iv2),
    salt: arrayBufferToBase64(salt),
    iv: arrayBufferToBase64(iv),
  };
}

/**
 * Decrypt private keys with password
 */
export async function decryptPrivateKeysWithPassword(
  encryptedSigningKey: string,
  encryptedEncryptionKey: string,
  salt: string,
  password: string
): Promise<{
  signingPrivateKey: string;
  encryptionPrivateKey: string;
}> {
  // Parse salt
  const saltBytes = base64ToUint8Array(salt);
  
  // Derive key from password
  const derivedKey = await deriveKeyFromPassword(password, saltBytes);
  
  // Decrypt signing key
  const [signingData, signingIv] = encryptedSigningKey.split(':');
  const decryptedSigning = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToUint8Array(signingIv) },
    derivedKey,
    base64ToArrayBuffer(signingData)
  );
  
  // Decrypt encryption key
  const [encryptionData, encryptionIv] = encryptedEncryptionKey.split(':');
  const decryptedEncryption = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToUint8Array(encryptionIv) },
    derivedKey,
    base64ToArrayBuffer(encryptionData)
  );
  
  return {
    signingPrivateKey: new TextDecoder().decode(decryptedSigning),
    encryptionPrivateKey: new TextDecoder().decode(decryptedEncryption),
  };
}

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
    { name: 'AES-GCM', iv },
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
    { name: 'AES-GCM', iv },
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

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
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

// Plain key bundle (only in memory, never stored to disk)
export interface KeyBundle {
  signingPublicKey: string;
  signingPrivateKey: string;
  encryptionPublicKey: string;
  encryptionPrivateKey: string;
}

// Encrypted key bundle (safe to store/download)
export interface EncryptedKeyBundle {
  version: 2; // Version 2 = password-encrypted keys
  signingPublicKey: string;
  encryptionPublicKey: string;
  encryptedSigningKey: string; // Encrypted with password
  encryptedEncryptionKey: string; // Encrypted with password
  salt: string; // PBKDF2 salt
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
 * Generate an encrypted key bundle (password-protected)
 */
export async function generateEncryptedKeyBundle(password: string): Promise<{
  bundle: EncryptedKeyBundle;
  plainKeys: KeyBundle;
}> {
  const plainKeys = await generateKeyBundle();
  
  const encrypted = await encryptPrivateKeysWithPassword(
    plainKeys.signingPrivateKey,
    plainKeys.encryptionPrivateKey,
    password
  );
  
  const bundle: EncryptedKeyBundle = {
    version: 2,
    signingPublicKey: plainKeys.signingPublicKey,
    encryptionPublicKey: plainKeys.encryptionPublicKey,
    encryptedSigningKey: encrypted.encryptedSigningKey,
    encryptedEncryptionKey: encrypted.encryptedEncryptionKey,
    salt: encrypted.salt,
  };
  
  return { bundle, plainKeys };
}

/**
 * Decrypt an encrypted key bundle with password
 */
export async function decryptKeyBundle(
  bundle: EncryptedKeyBundle,
  password: string
): Promise<KeyBundle> {
  const decrypted = await decryptPrivateKeysWithPassword(
    bundle.encryptedSigningKey,
    bundle.encryptedEncryptionKey,
    bundle.salt,
    password
  );
  
  return {
    signingPublicKey: bundle.signingPublicKey,
    signingPrivateKey: decrypted.signingPrivateKey,
    encryptionPublicKey: bundle.encryptionPublicKey,
    encryptionPrivateKey: decrypted.encryptionPrivateKey,
  };
}

/**
 * Check if a key bundle is encrypted (version 2) or plain (version 1/legacy)
 */
export function isEncryptedKeyBundle(bundle: any): bundle is EncryptedKeyBundle {
  return bundle && bundle.version === 2 && bundle.encryptedSigningKey;
}

export function downloadKeyBundle(bundle: EncryptedKeyBundle | KeyBundle, username: string): void {
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

export async function loadKeyBundleFromFile(file: File): Promise<EncryptedKeyBundle | KeyBundle> {
  const text = await file.text();
  return JSON.parse(text);
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
