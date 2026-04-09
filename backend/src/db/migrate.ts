import Database from 'better-sqlite3';
import { mkdir } from 'fs/promises';
import { dirname } from 'path';
import { libLogger } from '../lib/logger.js';

const DB_PATH = process.env.DATABASE_URL || './data/securevault.db';

// Ensure data directory exists
await mkdir(dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);

// Enable WAL mode
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  -- Users table
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

  -- Sessions table
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

  -- Files table
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
    created_at INTEGER DEFAULT (unixepoch())
  );

  -- File shares table
  CREATE TABLE IF NOT EXISTS file_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  -- Public shares table
  CREATE TABLE IF NOT EXISTS public_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    access_count INTEGER DEFAULT 0,
    max_access INTEGER
  );

  -- Audit logs table
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
    demo_session_id INTEGER,
    created_at INTEGER DEFAULT (unixepoch())
  );

  -- Notifications table
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

  -- Trusted devices table
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

  -- Settings table (key-value for VirusTotal API key, etc.)
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  -- Create indexes
  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
  CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_id);
  CREATE INDEX IF NOT EXISTS idx_files_uid ON files(uid);
  CREATE INDEX IF NOT EXISTS idx_file_shares_file ON file_shares(file_id);
  CREATE INDEX IF NOT EXISTS idx_file_shares_recipient ON file_shares(recipient_id);
  CREATE INDEX IF NOT EXISTS idx_public_shares_token ON public_shares(token);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_demo_session ON audit_logs(demo_session_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
  CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id);
  CREATE INDEX IF NOT EXISTS idx_trusted_devices_fingerprint ON trusted_devices(device_fingerprint);
`);

libLogger.info('Database tables created/verified');

// ============ MIGRATIONS ============
// Incremental column/table additions for databases created before the schema was extended.
// New tables should be added as CREATE TABLE IF NOT EXISTS in the block above.
// For greenfield deployments, the initial CREATE TABLE block handles everything.

function hasColumn(table: string, column: string): boolean {
  const columns = db.pragma(`table_info(${table})`) as { name: string }[];
  return columns.some((col) => col.name === column);
}

function hasTable(name: string): boolean {
  const rows = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").all(name) as { name: string }[];
  return rows.length > 0;
}

function runMigration(label: string, fn: () => void) {
  try {
    fn();
    libLogger.info(`Migration OK: ${label}`);
  } catch (error) {
    libLogger.error({ err: error }, `Migration failed: ${label}`);
    throw error;
  }
}

if (!hasColumn('files', 'uid'))
  runMigration('files.uid', () => {
    db.exec('ALTER TABLE files ADD COLUMN uid TEXT');
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_files_uid ON files(uid)');
  });

if (!hasColumn('users', 'avatar'))
  runMigration('users.avatar', () => db.exec('ALTER TABLE users ADD COLUMN avatar TEXT'));

if (!hasColumn('users', 'display_name'))
  runMigration('users.display_name', () => db.exec('ALTER TABLE users ADD COLUMN display_name TEXT'));

if (!hasTable('settings'))
  runMigration('settings table', () => db.exec('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)'));

if (!hasTable('pending_challenges'))
  runMigration('pending_challenges table', () => {
    db.exec(`
      CREATE TABLE pending_challenges (
        id TEXT PRIMARY KEY NOT NULL,
        challenge TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        device_link_pairing_id TEXT
      )
    `);
  });

if (!hasTable('pending_device_links'))
  runMigration('pending_device_links table', () => {
    db.exec(`
      CREATE TABLE pending_device_links (
        pairing_id TEXT PRIMARY KEY NOT NULL,
        link_secret TEXT NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        completed_at INTEGER,
        encrypted_keys TEXT,
        encrypted_keys_iv TEXT
      )
    `);
  });

// Migration 5: Add 'demo_session_id' column to files table (demo mode isolation)
if (!hasColumn('files', 'demo_session_id')) {
  libLogger.info('Running migration: Adding demo_session_id column to files table');
  try {
    db.exec('ALTER TABLE files ADD COLUMN demo_session_id INTEGER');
    db.exec('CREATE INDEX IF NOT EXISTS idx_files_demo_session ON files(demo_session_id)');
    libLogger.info('Migration successful: demo_session_id column added');
  } catch (error) {
    libLogger.error({ err: error }, 'Migration failed (demo_session_id)');
    throw error;
  }
}

// Migration 6: Add 'demo_session_id' column to audit_logs table (demo mode isolation)
if (!hasColumn('audit_logs', 'demo_session_id')) {
  libLogger.info('Running migration: Adding demo_session_id column to audit_logs table');
  try {
    db.exec('ALTER TABLE audit_logs ADD COLUMN demo_session_id INTEGER');
    db.exec('CREATE INDEX IF NOT EXISTS idx_audit_logs_demo_session ON audit_logs(demo_session_id)');
    libLogger.info('Migration successful: audit_logs.demo_session_id column added');
  } catch (error) {
    libLogger.error({ err: error }, 'Migration failed (audit_logs.demo_session_id)');
    throw error;
  }
}

libLogger.info('All database migrations completed');
db.close();
