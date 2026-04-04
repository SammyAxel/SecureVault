/**
 * Generate demo admin key bundle and a seeded SQLite database.
 *
 * Usage:  npx tsx backend/scripts/generate-demo-seed.ts
 *
 * Outputs:
 *   frontend/public/demo_admin_keys.json   – key file visitors download
 *   demo/securevault-demo.db               – seeded database to ship in Docker
 */

import { webcrypto } from 'node:crypto';
import { writeFileSync, mkdirSync, existsSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import Database from 'better-sqlite3';

const crypto = webcrypto as unknown as Crypto;

const ROOT = join(dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1')), '..', '..');
const DB_OUT = join(ROOT, 'demo', 'securevault-demo.db');
const KEYS_OUT = join(ROOT, 'frontend', 'public', 'demo_admin_keys.json');

function buf2b64(buf: ArrayBuffer): string {
  return Buffer.from(buf).toString('base64');
}

async function generateKeys() {
  const [signing, encryption] = await Promise.all([
    crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']),
    crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt'],
    ),
  ]);

  return {
    signingPublicKey: buf2b64(await crypto.subtle.exportKey('spki', signing.publicKey)),
    signingPrivateKey: buf2b64(await crypto.subtle.exportKey('pkcs8', signing.privateKey)),
    encryptionPublicKey: buf2b64(await crypto.subtle.exportKey('spki', encryption.publicKey)),
    encryptionPrivateKey: buf2b64(await crypto.subtle.exportKey('pkcs8', encryption.privateKey)),
  };
}

function createSeededDb(keys: { signingPublicKey: string; encryptionPublicKey: string }) {
  if (existsSync(DB_OUT)) unlinkSync(DB_OUT);
  mkdirSync(dirname(DB_OUT), { recursive: true });

  const db = new Database(DB_OUT);
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY NOT NULL,
      username TEXT UNIQUE NOT NULL,
      public_key_pem TEXT NOT NULL,
      encryption_public_key_pem TEXT,
      avatar TEXT,
      display_name TEXT,
      storage_used INTEGER DEFAULT 0,
      storage_quota INTEGER DEFAULT 524288000,
      is_admin INTEGER DEFAULT 0,
      is_suspended INTEGER DEFAULT 0,
      suspended_at INTEGER,
      totp_secret TEXT,
      totp_enabled INTEGER DEFAULT 0,
      backup_codes TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at INTEGER DEFAULT (unixepoch()),
      expires_at INTEGER NOT NULL,
      device_info TEXT,
      ip_address TEXT,
      user_agent TEXT,
      last_active INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      uid TEXT UNIQUE,
      filename TEXT NOT NULL,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_key TEXT NOT NULL,
      iv TEXT NOT NULL,
      storage_path TEXT,
      file_size INTEGER DEFAULT 0,
      is_folder INTEGER DEFAULT 0,
      parent_id TEXT REFERENCES files(id) ON DELETE CASCADE,
      is_deleted INTEGER DEFAULT 0,
      deleted_at INTEGER,
      demo_session_id INTEGER,
      created_at INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS file_shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_key TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS public_shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      access_count INTEGER DEFAULT 0,
      max_access INTEGER
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      resource_type TEXT,
      resource_id TEXT,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      read INTEGER DEFAULT 0,
      action_url TEXT,
      metadata TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS trusted_devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_fingerprint TEXT NOT NULL,
      device_name TEXT NOT NULL,
      browser TEXT,
      os TEXT,
      ip_address TEXT,
      last_used INTEGER DEFAULT (unixepoch()),
      created_at INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
    CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_id);
    CREATE INDEX IF NOT EXISTS idx_files_uid ON files(uid);
    CREATE INDEX IF NOT EXISTS idx_files_demo_session ON files(demo_session_id);
    CREATE INDEX IF NOT EXISTS idx_file_shares_file ON file_shares(file_id);
    CREATE INDEX IF NOT EXISTS idx_file_shares_recipient ON file_shares(recipient_id);
    CREATE INDEX IF NOT EXISTS idx_public_shares_token ON public_shares(token);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
    CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id);
    CREATE INDEX IF NOT EXISTS idx_trusted_devices_fingerprint ON trusted_devices(device_fingerprint);
  `);

  const userId = crypto.randomUUID();
  db.prepare(`
    INSERT INTO users (id, username, public_key_pem, encryption_public_key_pem, is_admin, storage_quota)
    VALUES (?, 'demo_admin', ?, ?, 1, 5368709120)
  `).run(userId, keys.signingPublicKey, keys.encryptionPublicKey);

  db.close();
  return userId;
}

async function main() {
  console.log('Generating demo admin key pair…');
  const keys = await generateKeys();

  console.log('Creating seeded database…');
  const userId = createSeededDb(keys);

  mkdirSync(dirname(KEYS_OUT), { recursive: true });
  writeFileSync(KEYS_OUT, JSON.stringify(keys, null, 2) + '\n');

  console.log(`\nDone!`);
  console.log(`  Keys    → ${KEYS_OUT}`);
  console.log(`  DB      → ${DB_OUT}`);
  console.log(`  User ID → ${userId}`);
  console.log(`  Username: demo_admin`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
