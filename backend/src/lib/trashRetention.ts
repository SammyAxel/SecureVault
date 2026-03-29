import { and, eq, lte } from 'drizzle-orm';

export async function purgeTrashedOlderThanDays(args: {
  // Keep typings loose here to avoid exporting internal schema types.
  db: any;
  schema: any;
  deleteFile: (relativePath: string) => Promise<boolean>;
  days: number;
  ownerId?: string;
}): Promise<{ deletedCount: number; reclaimedBytes: number }> {
  const { db, schema, deleteFile, days, ownerId } = args;
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const where = ownerId
    ? and(eq(schema.files.ownerId, ownerId), eq(schema.files.isDeleted, true), lte(schema.files.deletedAt, cutoff))
    : and(eq(schema.files.isDeleted, true), lte(schema.files.deletedAt, cutoff));

  const expired = await db.query.files.findMany({ where });
  if (expired.length === 0) return { deletedCount: 0, reclaimedBytes: 0 };

  // Delete physical blobs first (best-effort).
  for (const f of expired) {
    if (f.storagePath) await deleteFile(f.storagePath);
  }

  // Reclaim per-owner storage used.
  const reclaimedByOwner = new Map<string, number>();
  for (const f of expired) {
    reclaimedByOwner.set(f.ownerId, (reclaimedByOwner.get(f.ownerId) || 0) + (f.fileSize || 0));
  }

  for (const [ownerUserId, reclaimed] of reclaimedByOwner.entries()) {
    const user = await db.query.users.findFirst({ where: eq(schema.users.id, ownerUserId) });
    if (!user) continue;
    await db.update(schema.users)
      .set({ storageUsed: Math.max(0, (user.storageUsed || 0) - reclaimed) })
      .where(eq(schema.users.id, ownerUserId));
  }

  // Delete rows (CASCADE handles descendants if present).
  await db.delete(schema.files).where(where);

  const reclaimedBytes = expired.reduce((sum: number, f: any) => sum + (f.fileSize || 0), 0);
  return { deletedCount: expired.length, reclaimedBytes };
}

