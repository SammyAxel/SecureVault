import Database from 'better-sqlite3';
import { mkdir } from 'fs/promises';
import { dirname } from 'path';

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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );

  -- Notifications table
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    action_url TEXT,
    metadata TEXT,
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
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
`);

console.log('✅ Database tables created/verified');

// ============ MIGRATIONS ============
// Helper to check if column exists
function hasColumn(table: string, column: string): boolean {
  const columns = db.pragma(`table_info(${table})`) as any[];
  return columns.some((col) => col.name === column);
}

// Migration 1: Add 'uid' column to files table
if (!hasColumn('files', 'uid')) {
  console.log('⚡ Running migration: Adding uid column to files table...');
  try {
    db.exec('ALTER TABLE files ADD COLUMN uid TEXT');
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_files_uid ON files(uid)');
    console.log('✅ Migration successful: uid column added');
  } catch (error) {
    console.error('❌ Migration failed (uid):', error);
    throw error;
  }
}

// Migration 2: Add 'avatar' column to users table
if (!hasColumn('users', 'avatar')) {
  console.log('⚡ Running migration: Adding avatar column to users table...');
  try {
    db.exec('ALTER TABLE users ADD COLUMN avatar TEXT');
    console.log('✅ Migration successful: avatar column added');
  } catch (error) {
    console.error('❌ Migration failed (avatar):', error);
    throw error;
  }
}

// Migration 3: Add 'display_name' column to users table
if (!hasColumn('users', 'display_name')) {
  console.log('⚡ Running migration: Adding display_name column to users table...');
  try {
    db.exec('ALTER TABLE users ADD COLUMN display_name TEXT');
    console.log('✅ Migration successful: display_name column added');
  } catch (error) {
    console.error('❌ Migration failed (display_name):', error);
    throw error;
  }
}

// Migration 4: Create settings table if not exists
const tableList = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'").all() as { name: string }[];
if (tableList.length === 0) {
  console.log('⚡ Running migration: Creating settings table...');
  try {
    db.exec(`
      CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);
    console.log('✅ Migration successful: settings table created');
  } catch (error) {
    console.error('❌ Migration failed (settings):', error);
    throw error;
  }
}

console.log('✅ All database migrations completed!');
db.close();
