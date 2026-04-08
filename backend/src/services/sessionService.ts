import { db, schema } from '../db/index.js';
import { eq } from 'drizzle-orm';
import { generateToken, hashSHA256, getExpiryDate } from '../lib/crypto.js';

export async function createSession(userId: string, expiryHours: number, meta: {
  deviceInfo?: string; ipAddress?: string; userAgent?: string;
}): Promise<{ rawToken: string; expiresAt: Date }> {
  const rawToken = generateToken();
  const tokenHash = hashSHA256(rawToken);
  const expiresAt = getExpiryDate(expiryHours);

  await db.insert(schema.sessions).values({
    token: tokenHash,
    userId,
    expiresAt,
    deviceInfo: meta.deviceInfo,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  return { rawToken, expiresAt };
}

export async function deleteSessionByHash(tokenHash: string): Promise<void> {
  await db.delete(schema.sessions).where(eq(schema.sessions.token, tokenHash));
}

export async function deleteAllUserSessions(userId: string): Promise<void> {
  await db.delete(schema.sessions).where(eq(schema.sessions.userId, userId));
}
