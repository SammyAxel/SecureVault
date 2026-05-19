/**
 * Cleanup script: removes files inserted by simulate-attack.ts.
 * Identifies attack residue by missing keySignature (legitimate uploads always have one).
 */
import { db } from '../src/db/index';
import { files, users } from '../src/db/schema';
import { and, eq, isNull } from 'drizzle-orm';
import fs from 'node:fs/promises';

async function run() {
  const victim = await db.query.users.findFirst({ where: eq(users.username, 'admin1') });
  if (!victim) {
    console.log('admin1 not found — nothing to clean.');
    return;
  }

  const malicious = await db.select().from(files).where(
    and(eq(files.ownerId, victim.id), isNull(files.keySignature)),
  );

  if (malicious.length === 0) {
    console.log('No files without keySignature for admin1 — nothing to clean.');
    return;
  }

  console.log(`Found ${malicious.length} attack-residue file(s) to remove:`);
  for (const f of malicious) {
    console.log(`  - ${f.id} (${f.uid})`);
    if (f.storagePath) {
      try {
        await fs.unlink(f.storagePath);
        console.log(`    deleted disk file`);
      } catch (e: any) {
        console.log(`    disk file already gone (${e.code ?? 'unknown'})`);
      }
    }
    await db.delete(files).where(eq(files.id, f.id));
    console.log(`    deleted DB row`);
  }
  console.log('Cleanup complete.');
}

run().catch(console.error);
