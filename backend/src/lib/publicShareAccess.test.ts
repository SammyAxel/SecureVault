import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { sql } from 'drizzle-orm';
import { describe, it, expect, beforeEach } from 'vitest';

/** Minimal table matching consumeLimitedPublicShareAccess / recordUnlimitedPublicShareUnlock SQL. */
function createTestDb() {
  const sqlite = new Database(':memory:');
  sqlite.exec(`
    CREATE TABLE public_shares (
      id INTEGER PRIMARY KEY,
      access_count INTEGER DEFAULT 0,
      max_access INTEGER
    );
  `);
  return drizzle(sqlite);
}

function consumeLimited(db: ReturnType<typeof createTestDb>, shareId: number): boolean {
  const res = db.run(sql`
    UPDATE public_shares
    SET access_count = access_count + 1
    WHERE id = ${shareId}
      AND max_access IS NOT NULL
      AND access_count < max_access
  `);
  return (res?.changes ?? 0) > 0;
}

describe('public share access limits', () => {
  let testDb: ReturnType<typeof createTestDb>;

  beforeEach(() => {
    testDb = createTestDb();
    testDb.run(sql`INSERT INTO public_shares (id, access_count, max_access) VALUES (1, 0, 2)`);
    testDb.run(sql`INSERT INTO public_shares (id, access_count, max_access) VALUES (2, 0, NULL)`);
  });

  it('allows exactly max_access limited consumes', () => {
    expect(consumeLimited(testDb, 1)).toBe(true);
    expect(consumeLimited(testDb, 1)).toBe(true);
    expect(consumeLimited(testDb, 1)).toBe(false);
    const row = testDb.all(sql`SELECT access_count FROM public_shares WHERE id = 1`) as { access_count: number }[];
    expect(row[0].access_count).toBe(2);
  });

  it('does not consume limited rows when already at cap', () => {
    testDb.run(sql`UPDATE public_shares SET access_count = 2 WHERE id = 1`);
    expect(consumeLimited(testDb, 1)).toBe(false);
  });

  it('does not increment limited share via unlimited-only unlock SQL', () => {
    testDb.run(sql`
      UPDATE public_shares
      SET access_count = access_count + 1
      WHERE id = 1 AND max_access IS NULL
    `);
    const row = testDb.all(sql`SELECT access_count FROM public_shares WHERE id = 1`) as { access_count: number }[];
    expect(row[0].access_count).toBe(0);
  });

  it('increments unlimited share only via unlock path', () => {
    testDb.run(sql`
      UPDATE public_shares
      SET access_count = access_count + 1
      WHERE id = 2 AND max_access IS NULL
    `);
    const row = testDb.all(sql`SELECT access_count FROM public_shares WHERE id = 2`) as { access_count: number }[];
    expect(row[0].access_count).toBe(1);
  });
});
