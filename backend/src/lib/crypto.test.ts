import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, createSign } from 'crypto';
import {
  generateToken,
  generateUUID,
  hashSHA256,
  generateChallenge,
  safeCompare,
  getExpiryDate,
  verifyECDSASignature,
} from './crypto.js';

describe('generateToken', () => {
  it('returns a hex string of expected length', () => {
    const token = generateToken(16);
    expect(token).toMatch(/^[0-9a-f]{32}$/);
  });

  it('defaults to 32 bytes (64 hex chars)', () => {
    expect(generateToken()).toHaveLength(64);
  });
});

describe('generateUUID', () => {
  it('returns a valid UUID v4', () => {
    const uuid = generateUUID();
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe('hashSHA256', () => {
  it('produces consistent hashes', () => {
    const a = hashSHA256('hello');
    const b = hashSHA256('hello');
    expect(a).toBe(b);
  });

  it('produces different hashes for different inputs', () => {
    expect(hashSHA256('a')).not.toBe(hashSHA256('b'));
  });
});

describe('generateChallenge', () => {
  it('returns a base64 string', () => {
    const c = generateChallenge();
    expect(() => Buffer.from(c, 'base64')).not.toThrow();
    expect(Buffer.from(c, 'base64')).toHaveLength(32);
  });
});

describe('safeCompare', () => {
  it('returns true for equal strings', () => {
    expect(safeCompare('abc', 'abc')).toBe(true);
  });

  it('returns false for different strings', () => {
    expect(safeCompare('abc', 'abd')).toBe(false);
  });

  it('returns false for different length strings', () => {
    expect(safeCompare('ab', 'abc')).toBe(false);
  });
});

describe('getExpiryDate', () => {
  it('returns a date in the future', () => {
    const date = getExpiryDate(1);
    expect(date.getTime()).toBeGreaterThan(Date.now());
  });
});

describe('verifyECDSASignature', () => {
  it('verifies a valid P-256 signature', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });

    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const publicKeyBase64 = spkiDer.toString('base64');

    const challenge = 'test-challenge-data';
    const signer = createSign('SHA256');
    signer.update(challenge);
    const derSignature = signer.sign(privateKey);

    // Convert DER to P1363 (r||s) for WebCrypto compatibility
    const p1363Sig = derToP1363(derSignature, 32);
    const signatureBase64 = p1363Sig.toString('base64');

    expect(verifyECDSASignature(publicKeyBase64, challenge, signatureBase64)).toBe(true);
  });

  it('rejects an invalid signature', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const publicKeyBase64 = spkiDer.toString('base64');

    const badSig = Buffer.alloc(64, 0x42).toString('base64');
    expect(verifyECDSASignature(publicKeyBase64, 'challenge', badSig)).toBe(false);
  });

  it('returns false for malformed inputs', () => {
    expect(verifyECDSASignature('bad', 'challenge', 'bad')).toBe(false);
  });
});

/** Convert DER-encoded ECDSA signature to IEEE P1363 (r||s) format */
function derToP1363(der: Buffer, componentLength: number): Buffer {
  let offset = 2;
  if (der[1] & 0x80) offset += (der[1] & 0x7f);
  // Skip SEQUENCE tag + length
  offset = 2;
  // r INTEGER
  const rLen = der[offset + 1];
  let r = der.subarray(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;
  // s INTEGER
  const sLen = der[offset + 1];
  let s = der.subarray(offset + 2, offset + 2 + sLen);

  // Strip leading zeros
  while (r.length > componentLength) r = r.subarray(1);
  while (s.length > componentLength) s = s.subarray(1);

  // Pad to componentLength
  const result = Buffer.alloc(componentLength * 2);
  r.copy(result, componentLength - r.length);
  s.copy(result, componentLength * 2 - s.length);
  return result;
}
