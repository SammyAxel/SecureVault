import { sql } from 'drizzle-orm';
import { db } from '../db/index.js';

/**
 * For shares with max_access set: atomically increment access_count by one if still under the limit.
 * Use before streaming a public download so clients cannot bypass limits by skipping a separate endpoint.
 */
export function consumeLimitedPublicShareAccess(shareId: number): boolean {
  const res = db.run(sql`
    UPDATE public_shares
    SET access_count = access_count + 1
    WHERE id = ${shareId}
      AND max_access IS NOT NULL
      AND access_count < max_access
  `);
  return (res?.changes ?? 0) > 0;
}

/** For unlimited shares: record a successful passphrase unlock (analytics only). */
export function recordUnlimitedPublicShareUnlock(shareId: number): void {
  db.run(sql`
    UPDATE public_shares
    SET access_count = access_count + 1
    WHERE id = ${shareId}
      AND max_access IS NULL
  `);
}
