import { db, schema } from '../db/index.js';
import { libLogger } from '../lib/logger.js';

export async function logAudit(
  userId: string | null,
  username: string,
  action: string,
  resourceType?: string,
  resourceId?: string,
  details?: Record<string, unknown>,
  ipAddress?: string,
  userAgent?: string
) {
  try {
    await db.insert(schema.auditLogs).values({
      userId,
      username,
      action,
      resourceType,
      resourceId,
      details: details ? JSON.stringify(details) : null,
      ipAddress,
      userAgent,
    });
  } catch (error) {
    libLogger.error({ err: error }, 'Failed to log audit');
  }
}
