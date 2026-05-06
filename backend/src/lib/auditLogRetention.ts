import { lt } from 'drizzle-orm';

export async function purgeAuditLogsOlderThanDays(args: {
  db: any;
  schema: any;
  days: number;
}): Promise<{ deletedCount: number }> {
  const { db, schema, days } = args;
  if (days <= 0) return { deletedCount: 0 };

  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const rows = await db
    .select({ id: schema.auditLogs.id })
    .from(schema.auditLogs)
    .where(lt(schema.auditLogs.createdAt, cutoff));
  if (rows.length === 0) return { deletedCount: 0 };

  await db.delete(schema.auditLogs).where(lt(schema.auditLogs.createdAt, cutoff));
  return { deletedCount: rows.length };
}
