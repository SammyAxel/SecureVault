import { randomBytes, createHash } from 'crypto';

/**
 * Generate a secure random token
 */
export function generateToken(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Generate a UUID v4
 */
export function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Hash a string with SHA-256
 */
export function hashSHA256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Generate a random challenge for authentication
 */
export function generateChallenge(): string {
  return randomBytes(32).toString('base64');
}

/**
 * Timing-safe string comparison
 */
export function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Calculate expiry date
 */
export function getExpiryDate(hoursFromNow: number): Date {
  return new Date(Date.now() + hoursFromNow * 60 * 60 * 1000);
}
