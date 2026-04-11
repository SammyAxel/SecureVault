# SecureVault v2

End-to-end encrypted file sharing — backend **Fastify** + frontend **SolidJS**, schema **Drizzle** on **SQLite**.

## Tech stack

| Layer | Technology |
|-------|------------|
| **Backend** | Fastify (Node.js) + TypeScript |
| **Frontend** | SolidJS + TypeScript + TailwindCSS |
| **Database** | SQLite + Drizzle ORM |
| **Storage** | Filesystem (per user / month; see below) |
| **Encryption** | Web Crypto API (AES-GCM, RSA-OAEP, ECDSA) |

## Project structure

```
SecureVault/
├── backend/
│   ├── src/
│   │   ├── db/           # Drizzle schema, migrate bootstrap, DB connection
│   │   ├── lib/          # Storage, crypto helpers, integrations
│   │   ├── middleware/   # Auth
│   │   ├── routes/       # API routes
│   │   └── server.ts
│   ├── config/
│   │   └── storage.json.example   # Template for local storage config (optional)
│   ├── drizzle/          # Generated SQL migrations + meta
│   ├── drizzle.config.ts
│   └── package.json
├── frontend/
│   ├── src/
│   └── package.json
├── docs/
├── docker-compose.yml
├── Dockerfile
└── package.json          # Root scripts (dev, build, db:*)
```

---

## Quick start (development)

### Prerequisites

- **Node.js** v20+ ([nodejs.org](https://nodejs.org/))
- **npm** v10+ (bundled with Node)

### 1. Install dependencies

From the repository root:

```bash
npm install
```

This runs `postinstall` and installs **backend** and **frontend** dependencies automatically.

### 2. Run the app

```bash
npm run dev
```

- **Backend**: http://localhost:3000 (API + `GET /api/health`)
- **Frontend**: http://localhost:5173 (Vite dev server; API requests are proxied to the backend)

On startup, the backend runs [`backend/src/db/migrate.ts`](backend/src/db/migrate.ts) so SQLite tables exist (`backend/data/securevault.db` by default). Use the **Setup** flow in the UI to create the first admin user, or **Register** for additional users.

### 3. Drizzle CLI (optional)

Useful when you change the Drizzle schema and want migration files or Drizzle Studio:

```bash
npm run db:generate   # write SQL under backend/drizzle/ from schema changes
npm run db:migrate    # apply Drizzle migrations (drizzle-kit)
npm run db:studio     # open Drizzle Studio
```

> **Note:** Day-to-day local dev usually only needs `npm run dev`; the app still creates/updates core tables via `migrate.ts`. Breaking schema changes (e.g. column type changes on SQLite) may require **deleting the DB file** and blob storage — see [Database & user IDs](#database--user-ids).

### Production build (local)

```bash
npm run build
npm start
```

Serves the built SPA from the backend when `NODE_ENV=production`.

### Docker

```bash
docker compose up --build
```

App: http://localhost:3000 — data volume: DB under `/app/data`, files under `/app/uploads` (see [`docker-compose.yml`](docker-compose.yml)).

---

## Configuration

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Path to SQLite file | `./data/securevault.db` (relative to backend CWD) |
| `STORAGE_PATH` | Root directory for encrypted uploads | `./uploads` if no config file |
| `STORAGE_CONFIG_PATH` | JSON file for storage driver/path | `backend/config/storage.json` |
| `PORT` | HTTP port | `3000` |
| `HOST` | Bind address | `localhost` (dev), `0.0.0.0` (production) |
| `NODE_ENV` | `production` enables static frontend + stricter defaults | — |
| `CORS_ORIGIN` | CORS origin(s); unset allows flexible dev behavior | `true` (permissive) in dev |
| `LOG_LEVEL` | Pino log level | `debug` (dev), `info` (prod) |
| `TRASH_RETENTION_DAYS` | Purge trashed files older than N days | `30` |
| `TRASH_PURGE_INTERVAL_HOURS` | How often purge runs | `24` |
| `VIRUSTOTAL_API_KEY` | Optional scan-on-upload (also configurable in admin UI) | — |
| `MALWAREBAZAAR_API_KEY` | Optional MalwareBazaar integration | — |

Do **not** commit real `.env` files or API keys. Use a local `.env` (ignored by git) or your host’s secret store.

### Storage config file (optional)

To point uploads at a custom directory:

```bash
cp backend/config/storage.json.example backend/config/storage.json
# Edit local.path (or paths) as needed
```

`backend/config/storage.json` is **gitignored**; only the `.example` file belongs in the repo.

---

## Database & user IDs

- **Users** use a **UUID v4** string primary key (`users.id`), not sequential integers.
- Foreign keys (`sessions`, `files.owner_id`, shares, notifications, etc.) reference that text id.
- **File layout** on disk: `uploads/{user-uuid}/{YYYY-MM}/<random>.enc`.

If you upgrade from an older build that used integer user IDs, SQLite cannot safely migrate those columns in place: **delete the SQLite file**, clear the **uploads** (or storage root) you were using, then start fresh and run setup/register again.

---

## File storage layout

```
uploads/                          # or STORAGE_PATH / config local.path
└── {user-uuid}/
    └── {YYYY-MM}/
        └── {random}.enc
```

More detail: [`docs/STORAGE_PLAN.md`](docs/STORAGE_PLAN.md).

---

## Open source & repository hygiene

The [`.gitignore`](.gitignore) excludes typical local and sensitive artifacts, including:

- `node_modules/`, build output (`dist/`, `build/`)
- `data/`, `*.db`, SQLite WAL/SHM, `*.sqlite*`
- `uploads/`, root `/storage/`, `backend/config/storage.json`
- `.env`, `.env.*` (with exceptions for `*.example` templates)
- keys/certs patterns (`*.pem`, `*.p12`, `*.key`, `keys.json`, …)
- `docker-compose.override.yml`, coverage, caches, logs

**Before pushing or opening a PR:** confirm you are not adding secrets, real databases, or user upload directories.

---

## Features

- End-to-end encryption (AES-256-GCM); server stores ciphertext only  
- Passwordless ECDSA challenge–response auth  
- TOTP 2FA  
- Share with users or public links  
- Folders, trash / restore  
- Per-user quotas and optional admin tools  
- Rate limiting and security-related HTTP headers  

## API overview

### Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/register` | Create account |
| POST | `/api/auth/challenge` | Login challenge |
| POST | `/api/auth/verify` | Verify signature + session |
| POST | `/api/logout` | End session |
| GET | `/api/me` | Current user |
| POST | `/api/auth/2fa/setup` | Start 2FA |
| POST | `/api/auth/2fa/confirm` | Confirm 2FA |
| POST | `/api/auth/2fa/disable` | Disable 2FA |

### Files

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/files` | List files |
| POST | `/api/upload` | Upload |
| POST | `/api/folders` | Create folder |
| GET | `/api/files/:id/download` | Download |
| DELETE | `/api/files/:id` | Delete |
| POST | `/api/files/:id/restore` | Restore from trash |
| GET | `/api/trash` | List trash |

### Sharing

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/share` | Share with user |
| GET | `/api/shared-with-me` | Incoming shares |
| POST | `/api/share/public` | Public link |
| GET | `/api/public/:token` | Access public share |
| DELETE | `/api/share/public/:token` | Revoke public link |

## Security notes

1. **Private keys stay in the browser** — generated and held client-side.  
2. **Zero-knowledge for file contents** — server stores encrypted blobs and wrapped keys, not plaintext.  
3. **No password storage** — authentication is challenge/response with the user’s public key.  
4. **Rate limiting** — reduces brute-force noise on auth routes.  
5. **Security headers** — Helmet/CSP-style hardening in production.  

## Demo deployment

The `demo` branch ships a public demo profile: a pre-seeded admin account whose key file is served from the app itself, per-session upload limits, and an interactive tour.

### Quick start (Docker)

```bash
docker compose -f docker-compose.demo.yml up --build
```

App: http://localhost:3001 — on the login screen use **Download demo admin keys**, then sign in with username `demo_admin` and that file. After login, use **Tour** in the header for the guided walkthrough.

### Troubleshooting

**`git checkout demo` says it could be a local file and a branch** — the repo has a `demo/` directory, so Git can be ambiguous. Use:

```bash
git switch demo
# or: git checkout --no-guess demo
git pull origin demo
```

**Docker build fails on `npm ci` with “package.json and package-lock.json … not in sync”** — `npm ci` requires an exact, committed lockfile. Either run `npm install` in `frontend/` and `backend/` on your machine, commit the updated `package-lock.json` files, and pull again, or use the **`Dockerfile.demo` from this branch** (it uses `npm install`, which tolerates minor drift). If your `Dockerfile.demo` was changed locally (e.g. `npm ci` + Node 20), reset it with `git restore Dockerfile.demo` and rebuild.

### Local development (demo)

From the repo root, this starts the API and Vite together with `DEMO_MODE` and the seeded database:

```bash
npm run dev:demo
```

- Backend: http://localhost:3000  
- Frontend: http://localhost:5173 (proxies `/api` to the backend)

The normal `npm run dev` command also runs both servers but uses your default `backend/data/securevault.db` and does not enable demo mode unless you set `DEMO_MODE=true` yourself.

### How it works

| Feature | Detail |
|---------|--------|
| Seeded admin | `demo/securevault-demo.db` contains one admin user (`demo_admin`) whose public keys match `frontend/public/demo_admin_keys.json`. |
| No first-time setup | With `DEMO_MODE=true`, the app skips the setup wizard; `/api/setup/admin` is disabled. The login screen pre-fills the demo username from the server. |
| Session isolation | `DEMO_MODE=true` tags every uploaded file with the current session id. List/download/trash/share APIs only return files for the active session — different visitors using the same key file cannot see each other's files. |
| 25 MB cap | Each demo session can upload at most 25 MB total. |
| Logout cleanup | On logout the backend deletes all files (DB rows + blobs) created by that session. |
| Registration disabled | `POST /api/register` returns 403 in demo mode. |
| Interactive tour | A guided overlay (arrows + speech bubbles) starts on first visit after login; use **Tour** in the header to open it again. |
| Survey link | Set `VITE_SURVEY_URL` at build time (or in `docker-compose.demo.yml` as a build arg) to show a survey button in the banner. |

### Regenerating the seed

If you change the database schema or want fresh keys:

```bash
npm run demo:seed
```

This overwrites `frontend/public/demo_admin_keys.json` and `demo/securevault-demo.db`.

### Environment variables (demo-specific)

| Variable | Description | Default |
|----------|-------------|---------|
| `DEMO_MODE` | Enable demo session isolation + limits | `false` |
| `DEMO_USERNAME` | Username of the shared demo admin | `demo_admin` |
| `VITE_DEMO` | Frontend: show demo banner (set at build time) | — |
| `VITE_SURVEY_URL` | Frontend: Google Form URL for the survey button (set at build time) | — |

### Security note

The published key file means **anyone** can act as admin. Do **not** reuse the demo database, keys, or host for real data.

---

## Migration from v1

v2 is a full rewrite. There is no automatic import from v1: export anything you need from v1, deploy v2 with a **new** database and storage root, then upload again (files are re-encrypted for v2).

## License

MIT
