import { sqliteTable, text, integer, blob } from 'drizzle-orm/sqlite-core';
import { relations } from 'drizzle-orm';

// ============ USERS ============
export const users = sqliteTable('users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  username: text('username').unique().notNull(),
  publicKeyPem: text('public_key_pem').notNull(), // ECDSA signing key
  encryptionPublicKeyPem: text('encryption_public_key_pem'), // RSA-OAEP encryption key
  avatar: text('avatar'), // Base64 encoded avatar image
  displayName: text('display_name'), // Optional display name
  storageUsed: integer('storage_used').default(0),
  storageQuota: integer('storage_quota').default(524288000), // 500MB
  isAdmin: integer('is_admin', { mode: 'boolean' }).default(false),
  isSuspended: integer('is_suspended', { mode: 'boolean' }).default(false),
  suspendedAt: integer('suspended_at', { mode: 'timestamp' }),
  totpSecret: text('totp_secret'),
  totpEnabled: integer('totp_enabled', { mode: 'boolean' }).default(false),
  backupCodes: text('backup_codes'), // JSON array
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

// ============ SESSIONS ============
export const sessions = sqliteTable('sessions', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  token: text('token').unique().notNull(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  deviceInfo: text('device_info'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  lastActive: integer('last_active', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

// ============ FILES ============
export const files = sqliteTable('files', {
  id: text('id').primaryKey(), // UUID
  uid: text('uid').unique(), // Short URL-friendly ID (e.g., "abc123xyz")
  filename: text('filename').notNull(),
  ownerId: integer('owner_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  encryptedKey: text('encrypted_key').notNull(),
  iv: text('iv').notNull(),
  storagePath: text('storage_path'), // Path on filesystem (null for folders)
  fileSize: integer('file_size').default(0),
  isFolder: integer('is_folder', { mode: 'boolean' }).default(false),
  parentId: text('parent_id').references((): any => files.id, { onDelete: 'cascade' }),
  isDeleted: integer('is_deleted', { mode: 'boolean' }).default(false),
  deletedAt: integer('deleted_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

// ============ FILE SHARES (User-to-User) ============
export const fileShares = sqliteTable('file_shares', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  fileId: text('file_id').notNull().references(() => files.id, { onDelete: 'cascade' }),
  recipientId: integer('recipient_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  encryptedKey: text('encrypted_key').notNull(), // File key encrypted with recipient's public key
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

// ============ PUBLIC SHARES (Link-based) ============
export const publicShares = sqliteTable('public_shares', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  fileId: text('file_id').notNull().references(() => files.id, { onDelete: 'cascade' }),
  token: text('token').unique().notNull(), // UUID for public link
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
  accessCount: integer('access_count').default(0),
  maxAccess: integer('max_access'), // Optional: limit number of accesses
});

// ============ AUDIT LOGS ============
export const auditLogs = sqliteTable('audit_logs', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').references(() => users.id, { onDelete: 'set null' }),
  username: text('username').notNull(), // Store username in case user is deleted
  action: text('action').notNull(), // LOGIN, LOGOUT, UPLOAD, DOWNLOAD, DELETE, SHARE, etc.
  resourceType: text('resource_type'), // FILE, FOLDER, USER, SESSION, etc.
  resourceId: text('resource_id'), // ID of the affected resource
  details: text('details'), // JSON string with additional details
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

// ============ SETTINGS (key-value, e.g. VirusTotal API key) ============
export const settings = sqliteTable('settings', {
  key: text('key').primaryKey(),
  value: text('value'),
});

// ============ NOTIFICATIONS ============
export const notifications = sqliteTable('notifications', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  type: text('type').notNull(), // 'file_shared', 'admin_action', 'storage_warning', 'public_access', etc.
  title: text('title').notNull(),
  message: text('message').notNull(),
  read: integer('read', { mode: 'boolean' }).default(false),
  actionUrl: text('action_url'), // Optional URL to navigate to
  metadata: text('metadata'), // JSON string with additional data
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

// ============ RELATIONS ============
export const usersRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  files: many(files),
  sharedFiles: many(fileShares),
  auditLogs: many(auditLogs),
  notifications: many(notifications),
}));

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, { fields: [sessions.userId], references: [users.id] }),
}));

export const filesRelations = relations(files, ({ one, many }) => ({
  owner: one(users, { fields: [files.ownerId], references: [users.id] }),
  parent: one(files, { fields: [files.parentId], references: [files.id] }),
  children: many(files),
  shares: many(fileShares),
  publicShares: many(publicShares),
}));

export const fileSharesRelations = relations(fileShares, ({ one }) => ({
  file: one(files, { fields: [fileShares.fileId], references: [files.id] }),
  recipient: one(users, { fields: [fileShares.recipientId], references: [users.id] }),
}));

export const publicSharesRelations = relations(publicShares, ({ one }) => ({
  file: one(files, { fields: [publicShares.fileId], references: [files.id] }),
}));

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, { fields: [auditLogs.userId], references: [users.id] }),
}));

export const notificationsRelations = relations(notifications, ({ one }) => ({
  user: one(users, { fields: [notifications.userId], references: [users.id] }),
}));

// ============ TYPE EXPORTS ============
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type File = typeof files.$inferSelect;
export type NewFile = typeof files.$inferInsert;
export type FileShare = typeof fileShares.$inferSelect;
export type NewFileShare = typeof fileShares.$inferInsert;
export type Notification = typeof notifications.$inferSelect;
export type NewNotification = typeof notifications.$inferInsert;
export type PublicShare = typeof publicShares.$inferSelect;
export type NewPublicShare = typeof publicShares.$inferInsert;
export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;
export type Setting = typeof settings.$inferSelect;
export type NewSetting = typeof settings.$inferInsert;
