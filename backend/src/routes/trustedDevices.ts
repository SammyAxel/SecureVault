import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, desc } from 'drizzle-orm';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { z } from 'zod';
import crypto from 'crypto';

// ============ TRUSTED DEVICES ROUTES ============

export async function trustedDevicesRoutes(app: FastifyInstance): Promise<void> {
  
  // ============ LIST TRUSTED DEVICES ============
  app.get('/api/trusted-devices', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const devices = await db.query.trustedDevices.findMany({
      where: eq(schema.trustedDevices.userId, user.id),
      orderBy: [desc(schema.trustedDevices.lastUsed)],
    });
    
    return {
      ok: true,
      devices: devices.map(d => ({
        id: d.id,
        deviceName: d.deviceName,
        browser: d.browser,
        os: d.os,
        ipAddress: d.ipAddress,
        lastUsed: d.lastUsed,
        createdAt: d.createdAt,
      })),
    };
  });
  
  // ============ REMOVE TRUSTED DEVICE ============
  app.delete('/api/trusted-devices/:id', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const deviceId = parseInt((request.params as any).id);
    
    if (isNaN(deviceId)) {
      return reply.status(400).send({ ok: false, msg: 'Invalid device ID' });
    }
    
    // Verify device belongs to user
    const device = await db.query.trustedDevices.findFirst({
      where: and(
        eq(schema.trustedDevices.id, deviceId),
        eq(schema.trustedDevices.userId, user.id)
      ),
    });
    
    if (!device) {
      return reply.status(404).send({ ok: false, msg: 'Device not found' });
    }
    
    await db.delete(schema.trustedDevices)
      .where(eq(schema.trustedDevices.id, deviceId));
    
    return { ok: true, msg: 'Device removed' };
  });
  
  // ============ REMOVE ALL TRUSTED DEVICES ============
  app.delete('/api/trusted-devices', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    await db.delete(schema.trustedDevices)
      .where(eq(schema.trustedDevices.userId, user.id));
    
    return { ok: true, msg: 'All devices removed' };
  });
}

// ============ HELPER FUNCTIONS ============

export async function checkTrustedDevice(userId: number, deviceFingerprint: string): Promise<boolean> {
  const device = await db.query.trustedDevices.findFirst({
    where: and(
      eq(schema.trustedDevices.userId, userId),
      eq(schema.trustedDevices.deviceFingerprint, deviceFingerprint)
    ),
  });
  
  return !!device;
}

export async function addTrustedDevice(
  userId: number,
  deviceFingerprint: string,
  deviceName: string,
  browser: string | null,
  os: string | null,
  ipAddress: string | undefined
): Promise<void> {
  // Check if device already exists
  const existing = await db.query.trustedDevices.findFirst({
    where: and(
      eq(schema.trustedDevices.userId, userId),
      eq(schema.trustedDevices.deviceFingerprint, deviceFingerprint)
    ),
  });
  
  if (existing) {
    // Update last used
    await db.update(schema.trustedDevices)
      .set({ lastUsed: new Date(), ipAddress })
      .where(eq(schema.trustedDevices.id, existing.id));
  } else {
    // Add new device
    await db.insert(schema.trustedDevices).values({
      userId,
      deviceFingerprint,
      deviceName,
      browser,
      os,
      ipAddress,
    });
  }
}

export async function updateTrustedDeviceLastUsed(
  userId: number,
  deviceFingerprint: string
): Promise<void> {
  await db.update(schema.trustedDevices)
    .set({ lastUsed: new Date() })
    .where(and(
      eq(schema.trustedDevices.userId, userId),
      eq(schema.trustedDevices.deviceFingerprint, deviceFingerprint)
    ));
}

// Generate a hash of device properties for fingerprint
export function generateDeviceFingerprint(
  userAgent: string,
  ipAddress: string,
  additionalData?: string
): string {
  const data = `${userAgent}|${ipAddress}|${additionalData || ''}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}
