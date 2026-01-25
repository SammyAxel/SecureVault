# SecureVault v2

End-to-End Encrypted File Sharing — Migrated to **Fastify + SolidJS + Drizzle**

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Fastify (Node.js) + TypeScript |
| **Frontend** | SolidJS + TypeScript + TailwindCSS |
| **Database** | SQLite + Drizzle ORM |
| **Storage** | Filesystem (organized by user/date) |
| **Encryption** | Web Crypto API (AES-GCM, RSA-OAEP, ECDSA) |

## Project Structure

```
v2/
├── backend/
│   ├── src/
│   │   ├── db/           # Drizzle schema & connection
│   │   ├── lib/          # Utilities (storage, crypto)
│   │   ├── middleware/   # Auth middleware
│   │   ├── routes/       # API routes
│   │   └── server.ts     # Fastify app
│   ├── drizzle.config.ts
│   └── package.json
│
├── frontend/
│   ├── src/
│   │   ├── components/   # SolidJS components
│   │   ├── lib/          # API client, crypto utils
│   │   ├── stores/       # State management
│   │   └── App.tsx
│   ├── vite.config.ts
│   └── package.json
│
├── docker-compose.yml
├── Dockerfile
└── package.json
```

## Quick Start

### Development

```bash
# Install dependencies
npm install
cd backend && npm install
cd ../frontend && npm install
cd ..

# Generate database schema
npm run db:generate
npm run db:migrate

# Run development servers
npm run dev
```

This starts:
- Backend: http://localhost:3000
- Frontend: http://localhost:5173 (proxies API to backend)

### Production (Docker)

```bash
docker-compose up --build
```

App available at http://localhost:3000

## Features

- ✅ **End-to-End Encryption** — Files encrypted client-side with AES-256-GCM
- ✅ **Zero-Knowledge** — Server only stores encrypted blobs
- ✅ **Passwordless Auth** — ECDSA challenge-response authentication
- ✅ **2FA Support** — TOTP-based two-factor authentication
- ✅ **File Sharing** — Share with users or via public links
- ✅ **Folder Support** — Organize files in folders
- ✅ **Trash/Restore** — Soft delete with recovery
- ✅ **Storage Quotas** — Per-user storage limits
- ✅ **Rate Limiting** — Anti-brute-force protection
- ✅ **Security Headers** — HSTS, CSP, XSS protection

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/register` | Create account |
| POST | `/api/auth/challenge` | Get login challenge |
| POST | `/api/auth/verify` | Verify signature + login |
| POST | `/api/logout` | End session |
| GET | `/api/me` | Get current user |
| POST | `/api/auth/2fa/setup` | Setup 2FA |
| POST | `/api/auth/2fa/confirm` | Confirm 2FA |
| POST | `/api/auth/2fa/disable` | Disable 2FA |

### Files
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/files` | List files |
| POST | `/api/upload` | Upload file |
| POST | `/api/folders` | Create folder |
| GET | `/api/files/:id/download` | Download file |
| DELETE | `/api/files/:id` | Delete file |
| POST | `/api/files/:id/restore` | Restore from trash |
| GET | `/api/trash` | List trash |

### Sharing
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/share` | Share with user |
| GET | `/api/shared-with-me` | Files shared with me |
| POST | `/api/share/public` | Create public link |
| GET | `/api/public/:token` | Access public share |
| DELETE | `/api/share/public/:token` | Delete public link |

## Database Commands

```bash
# Generate migrations from schema changes
npm run db:generate

# Apply migrations
npm run db:migrate

# Open Drizzle Studio (DB browser)
npm run db:studio
```

## File Storage

Files are stored in organized directories:

```
uploads/
├── {user_id}/
│   ├── {YYYY-MM}/
│   │   ├── {random}.enc
│   │   └── {random}.enc
```

## Security Notes

1. **Private keys never leave the browser** — Generated and stored client-side
2. **Zero-knowledge architecture** — Server cannot decrypt files
3. **Challenge-response auth** — No passwords stored
4. **Rate limiting** — Prevents brute-force attacks
5. **Security headers** — CSP, HSTS, X-XSS-Protection

## Migration from v1

The v2 codebase is a complete rewrite. To migrate:

1. Export data from v1 (if needed)
2. Run v2 with fresh database
3. Re-upload files (they'll be re-encrypted)

## License

MIT
