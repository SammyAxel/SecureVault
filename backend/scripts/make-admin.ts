/**
 * Script to promote a user to admin
 * Usage: npx tsx scripts/make-admin.ts <username>
 */

import { db, schema } from '../src/db/index.js';
import { eq } from 'drizzle-orm';

async function makeAdmin(username: string) {
  if (!username) {
    console.error('❌ Usage: npx tsx scripts/make-admin.ts <username>');
    process.exit(1);
  }

  // Find user
  const user = await db.query.users.findFirst({
    where: eq(schema.users.username, username),
  });

  if (!user) {
    console.error(`❌ User "${username}" not found`);
    process.exit(1);
  }

  if (user.isAdmin) {
    console.log(`✅ User "${username}" is already an admin`);
    process.exit(0);
  }

  // Update to admin
  await db.update(schema.users)
    .set({ isAdmin: true })
    .where(eq(schema.users.id, user.id));

  console.log(`✅ User "${username}" is now an admin!`);
  process.exit(0);
}

const username = process.argv[2];
makeAdmin(username);
