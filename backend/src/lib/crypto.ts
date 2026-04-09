import { randomBytes, createHash, createVerify, createPublicKey, timingSafeEqual, createCipheriv, createDecipheriv } from 'crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname, resolve } from 'path';
import { libLogger } from './logger.js';

export function generateToken(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

export function generateUUID(): string {
  return crypto.randomUUID();
}

export function generateUID(): string {
  return crypto.randomUUID();
}

export function hashSHA256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function generateChallenge(): string {
  return randomBytes(32).toString('base64');
}

/**
 * Verify an ECDSA P-256 SHA-256 signature.
 * @param publicKeyBase64 SPKI public key encoded as base64 (raw DER, no PEM headers)
 * @param challenge       The original challenge string that was signed
 * @param signatureBase64 The signature bytes encoded as base64 (IEEE P1363 / raw r||s format from WebCrypto)
 */
export function verifyECDSASignature(
  publicKeyBase64: string,
  challenge: string,
  signatureBase64: string
): boolean {
  try {
    const publicKeyDer = Buffer.from(publicKeyBase64, 'base64');
    const signatureRaw = Buffer.from(signatureBase64, 'base64');

    // WebCrypto ECDSA P-256 produces IEEE P1363 signatures (64 bytes: r || s).
    // Node.js crypto.createVerify expects DER-encoded ASN.1 signatures.
    const signatureDer = p1363ToDer(signatureRaw);

    const keyObject = createPublicKeyFromSpki(publicKeyDer);
    const verifier = createVerify('SHA256');
    verifier.update(challenge);
    return verifier.verify(keyObject, signatureDer);
  } catch (err) {
    libLogger.warn({ err, publicKeyLen: publicKeyBase64?.length, sigLen: signatureBase64?.length },
      'ECDSA signature verification threw — treating as invalid');
    return false;
  }
}

function createPublicKeyFromSpki(spkiDer: Buffer) {
  return createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}

/** Convert a P1363 (r||s) ECDSA signature to DER-encoded ASN.1 for Node.js verification. */
function p1363ToDer(raw: Buffer): Buffer {
  const half = raw.length / 2;
  let r = raw.subarray(0, half);
  let s = raw.subarray(half);

  // Strip leading zeros but keep one if high bit is set
  while (r.length > 1 && r[0] === 0 && !(r[1] & 0x80)) r = r.subarray(1);
  while (s.length > 1 && s[0] === 0 && !(s[1] & 0x80)) s = s.subarray(1);

  // Prepend 0x00 if high bit is set (ASN.1 positive integer)
  if (r[0] & 0x80) r = Buffer.concat([Buffer.from([0x00]), r]);
  if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0x00]), s]);

  const rTlv = Buffer.concat([Buffer.from([0x02, r.length]), r]);
  const sTlv = Buffer.concat([Buffer.from([0x02, s.length]), s]);
  const seqLen = rTlv.length + sTlv.length;
  return Buffer.concat([Buffer.from([0x30, seqLen]), rTlv, sTlv]);
}

export function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function getExpiryDate(hoursFromNow: number): Date {
  return new Date(Date.now() + hoursFromNow * 60 * 60 * 1000);
}

// ============ TOTP SECRET ENCRYPTION AT REST (AES-256-GCM) ============

let _totpKey: Buffer | null = null;

function getTotpEncryptionKey(): Buffer {
  if (_totpKey) return _totpKey;
  const keyPath = resolve('./data/totp.key');
  if (existsSync(keyPath)) {
    _totpKey = readFileSync(keyPath);
  } else {
    _totpKey = randomBytes(32);
    mkdirSync(dirname(keyPath), { recursive: true });
    writeFileSync(keyPath, _totpKey, { mode: 0o600 });
  }
  return _totpKey;
}

export function encryptTotpSecret(secret: string): string {
  const key = getTotpEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

/**
 * Decrypt a TOTP secret. Falls back to returning the raw string if decryption
 * fails, which handles legacy unencrypted secrets transparently.
 */
export function decryptTotpSecret(encrypted: string): string {
  try {
    const key = getTotpEncryptionKey();
    const data = Buffer.from(encrypted, 'base64');
    if (data.length < 29) return encrypted;
    const iv = data.subarray(0, 12);
    const tag = data.subarray(12, 28);
    const ciphertext = data.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(ciphertext).toString('utf8') + decipher.final('utf8');
  } catch {
    return encrypted;
  }
}
