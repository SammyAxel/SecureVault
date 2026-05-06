# Change log & features (SecureVault)

Use this file to **track implemented features and changes** (thesis / day-to-day development).  
Add an entry **whenever** you ship a feature, a significant fix, or an architecture decision.

## How to use

- **Order:** newest entry **on top** (right after this section).
- **One** topic per entry; multiple bullets under the same date are fine.
- Keep it short: **what changed**, main **files/areas** (optional), and **how to use** if needed (env, UI).

---

## 2026-04-25 — feature inventory (full codebase scan)

Inventory of what **actually exists in the repo**, derived from a scan of `backend/src/routes/*.ts`, `backend/src/server.ts`, `backend/src/middleware/auth.ts`, `backend/src/db/schema.ts`, `backend/src/lib/*.ts`, `backend/src/services/auditService.ts`, `frontend/src/lib/api.ts`, `frontend/src/App.tsx`, `frontend/src/lib/routes.ts`, `frontend/src/components/FilePreview.tsx`, root `package.json`, and `docs/` — **not** only from `README.md`. This is not a Git commit log.

### Database (Drizzle / SQLite)

Tables and main roles: **`users`** (ECDSA + RSA-OAEP PEMs, avatar, display name, `storageUsed` / `storageQuota`, admin flag, suspend fields, TOTP + backup codes); **`sessions`** (hashed token, expiry, device/IP/UA, `lastActive`, `tokenRotatedAt`); **`files`** (hierarchy, `uid`, ciphertext metadata, soft-delete / `deletedAt`, optional `demoSessionId`); **`file_shares`**; **`public_shares`** + **`public_share_items`** (folder public links); **`audit_logs`**; **`settings`** (key-value, e.g. VT/MB); **`notifications`**; **`pending_challenges`**; **`pending_device_links`**; **`trusted_devices`**.

### HTTP API (Fastify routes)

- **Health:** `GET /api/health`.
- **Auth / setup (`routes/auth.ts`):** `GET /api/setup/status`, `POST /api/setup/admin`, `POST /api/register` (stricter rate limit), `POST /api/auth/challenge`, `POST /api/auth/verify`, device link `POST /api/auth/device-link/create`, `GET …/status`, `POST …/challenge`, `POST …/verify`, `POST /api/logout`, `GET /api/me`, 2FA `POST /api/auth/2fa/setup|confirm|disable`, `GET /api/users/:username/publickey` (for wrapping keys when sharing), `PUT /api/profile`, `GET /api/sessions`, `DELETE /api/sessions/:id`, `POST /api/sessions/revoke-all`, `DELETE /api/account`.
- **Files (`routes/files.ts`):** `GET /api/files`, `GET /api/f/:uid`, `POST /api/upload`, `POST /api/folders`, `GET /api/folders`, `GET /api/files/:fileId/download`, `DELETE /api/files/:fileId`, `POST …/restore`, `GET /api/trash`, `DELETE /api/trash/empty`, `PATCH /api/files/:fileId/rename`, `PATCH …/move`.
- **Share (`routes/share.ts`):** `POST /api/share`, `GET /api/shared-with-me`, `DELETE /api/share/:fileId/:recipientId`, `GET /api/files/:fileId/shares`, `POST /api/share/public`, unauthenticated `GET /api/public/:token`, `GET …/file/:fileId/download`, `GET …/download`, `DELETE /api/share/public/:token`.
- **Admin (`routes/admin.ts`):** `GET|PATCH /api/admin/settings`, VirusTotal keys `GET|POST|PATCH|DELETE /api/admin/virustotal-keys…`, MalwareBazaar `GET|POST|DELETE /api/admin/malwarebazaar`, `GET /api/admin/stats`, `GET /api/admin/users` (pagination + username search), `PATCH …/users/:userId/suspend`, `PATCH …/quota`, `GET /api/admin/audit-logs`, `GET /api/admin/users/:userId/sessions`, `DELETE /api/admin/sessions/:sessionId`.
- **Notifications (`routes/notifications.ts`):** `GET /api/notifications`, `PATCH /api/notifications/:id/read`, `PATCH /api/notifications/read-all`, `DELETE /api/notifications/:id`, `DELETE /api/notifications` (clear all).
- **Trusted devices (`routes/trustedDevices.ts`):** `GET /api/trusted-devices`, `DELETE /api/trusted-devices/:id`, `DELETE /api/trusted-devices` (clear all).
- **User audit (`routes/audit.ts`):** `GET /api/audit-logs` (authenticated user’s own log).

### Server stack (`server.ts` + plugins)

- **Fastify:** large body/upload limits (e.g. 500 MB), long request timeout; **Pino** logging (`LOG_LEVEL`, pretty in dev).
- **Security:** `@fastify/cookie`, **CSRF** hook (`lib/sessionCookies.ts`), **Helmet** with CSP (fonts, `blob:`/`data:` where needed), optional **HSTS** from `ENABLE_HSTS` / `HSTS_MAX_AGE_SECONDS`.
- **CORS** from `CORS_ORIGIN` (comma-separated) or permissive in dev; **global rate limit** 100 req/min keyed by **client IP** (`lib/clientIp.ts`); **stricter limits** on credential routes in `auth.ts`.
- **Multipart** uploads; **static SPA** from `frontend/dist` when `NODE_ENV=production`.
- **DB:** run `migrate.ts` on boot; **retention jobs:** trash purge + optional `audit_logs` purge on the same interval (`TRASH_PURGE_INTERVAL_HOURS`).

### Backend libraries & services

- **`lib/crypto.ts`:** hashing, tokens, etc. (used for sessions).
- **`lib/storage.ts`:** encrypted blob paths and delete helpers.
- **`lib/uploadMalwareScan.ts`:** parallel **VirusTotal** + **MalwareBazaar** buffer scans on upload pipeline.
- **`lib/virustotal.ts`**, **`lib/malwarebazaar.ts`:** integrations + settings persistence.
- **`lib/sanitize.ts`:** safe **Content-Disposition** filenames (header injection mitigation).
- **`lib/demo.ts`:** `DEMO_MODE`, `DEMO_USERNAME`, per-session demo scoping helper, 25 MB session upload cap constant.
- **`lib/trashRetention.ts`**, **`lib/auditLogRetention.ts`:** scheduled purges.
- **`services/auditService.ts`:** `logAudit()` inserts into `audit_logs` (best-effort, errors logged).

### Auth middleware behavior (`middleware/auth.ts`)

- Session from cookie (or legacy Bearer if enabled); **suspended** users blocked; optional **IP + User-Agent binding** with optional IPv4 /24 relaxation; **opaque token rotation** on an interval (`SESSION_ROTATE_HOURS`) with cookie refresh.

### Frontend (SolidJS)

- **Routing / shell:** `App.tsx` — setup gate, login/register/**device-link** path, lazy **Dashboard**, **Profile**, **Admin**, **PublicShare** (`/share/:token`); drive sections **Home / Drive / Shared / Trash** + **search** URLs (`lib/routes.ts`); **mobile drawer**, vault **search** (`/` and `Ctrl/Cmd+K`); **keyboard shortcuts** modal (`?` / `Shift+/`); **demo** banner + **tour**; **Web Crypto** missing banner.
- **API client:** mirrored calls in `lib/api.ts` for all major endpoints above (including admin VT multi-key, MB, notifications, trusted devices, audit).
- **i18n:** English + Malay (`lib/i18n.ts`, locale in localStorage).
- **Theme:** light / dark / system (`lib/theme.ts`).
- **Previews (`FilePreview.tsx` helpers):** images, **video**, **audio**, **PDF**, **CSV**, **Excel** (xlsx/xls), **Word** (docx), plus many **text/code** extensions (txt, md, json, js, ts, html, css, py, xml, yaml, ini, log, sh, sql); lazy **Word** / **Excel** chunks.
- **Other UI:** toast + global confirm store, skeletons, motion delays, **BlobSavePrompt** / `downloadBlob`, **AvatarCropper**, breadcrumb, **NotificationCenter**, **ShareModal** (public link types: permanent / days / view limit; passphrase + folder multi-file wrapping), **DeviceLinkModal**, profile activity strings, etc.

### Tooling & tests

- **Root scripts:** `dev`, `dev:demo`, `build`, `start`, Drizzle `db:*`, **`demo:seed`** (`backend/scripts/generate-demo-seed.ts`).
- **Backend tests (Vitest):** `lib/sanitize.test.ts`, `lib/crypto.test.ts`; **frontend:** `lib/api.test.ts`, `lib/routes.test.ts`.

### Docs & ops

- **`docs/STORAGE_PLAN.md`** — storage layout notes.
- **Docker:** compose + Dockerfile (see repo root); env templates in **`.env.example`**.

### Cryptography & product semantics (unchanged summary)

- **E2E file crypto** in the browser (AES-GCM, wrapped keys); server stores ciphertext; **passwordless ECDSA** login; **2FA TOTP** + backup codes; **share to user** or **public link** (optional passphrase/KDF); **device link** and **trusted devices**.

### Audit log retention (SQLite)

- `AUDIT_LOG_RETENTION_DAYS`: `0` = never delete; positive = delete rows older than N days, same schedule as trash purge. Implementation: `backend/src/lib/auditLogRetention.ts` + `server.ts` + `config.ts`.

---

*For day-to-day changes, add a new dated section **above** this block and describe only the delta. Re-run a full scan occasionally to refresh this inventory.*

## Template (copy above this section)

```text
## YYYY-MM-DD

### Short title

- **Summary:** …
- **Files / area:** … (optional)
- **Usage / env / UI:** … (optional)
```
