import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import multipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { readFile } from 'fs/promises';

import { getClientIp } from './lib/clientIp.js';
import { db, schema } from './db/index.js';
import { deleteFile } from './lib/storage.js';
import { purgeTrashedOlderThanDays } from './lib/trashRetention.js';
import { authRoutes } from './routes/auth.js';
import { fileRoutes } from './routes/files.js';
import { shareRoutes } from './routes/share.js';
import { adminRoutes } from './routes/admin.js';
import notificationRoutes from './routes/notifications.js';
import { trustedDevicesRoutes } from './routes/trustedDevices.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const isDev = process.env.NODE_ENV !== 'production';

const app = Fastify({
  requestTimeout: 10 * 60 * 1000, // 10 minutes for large file uploads
  bodyLimit: 500 * 1024 * 1024, // 500MB max body size
  logger: isDev
    ? {
        level: process.env.LOG_LEVEL || 'info',
        transport: {
          target: 'pino-pretty',
          options: { colorize: true },
        },
      }
    : {
        level: process.env.LOG_LEVEL || 'info',
      },
});

// ============ PLUGINS ============

// CORS
await app.register(cors, {
  origin: process.env.CORS_ORIGIN || true,
  credentials: true,
});

// Security headers
await app.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      mediaSrc: ["'self'", 'blob:'], // Allow video/audio preview
      objectSrc: ["'self'", 'blob:'], // Allow PDF and other object embeds
      frameSrc: ["'self'", 'blob:'], // Allow iframe preview
      connectSrc: ["'self'", 'blob:'], // Allow fetch from blob URLs for text preview
      workerSrc: ["'self'", 'blob:'],
      upgradeInsecureRequests: null, // Disable HTTPS upgrade for HTTP-only deployments
    },
  },
  hsts: false, // Disable HSTS for HTTP deployments
});

// Rate limiting (use client IP from proxy headers when behind reverse proxy)
await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (request) => getClientIp(request),
});

// Multipart (file uploads) — optimize for large files through proxies
await app.register(multipart, {
  limits: {
    fileSize: 500 * 1024 * 1024, // 500MB max per file
  },
});

// Serve static frontend files in production
if (process.env.NODE_ENV === 'production') {
  await app.register(fastifyStatic, {
    root: join(__dirname, '../frontend/dist'),
    prefix: '/',
  });
}

// ============ ROUTES ============
await app.register(authRoutes);
await app.register(fileRoutes);
await app.register(shareRoutes);
await app.register(adminRoutes);
await app.register(notificationRoutes);
await app.register(trustedDevicesRoutes);

// Health check
app.get('/api/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));

// SPA fallback - serve index.html for all non-API routes
if (process.env.NODE_ENV === 'production') {
  app.setNotFoundHandler(async (request, reply) => {
    // Don't serve index.html for API routes
    if (request.url.startsWith('/api/')) {
      return reply.status(404).send({ error: 'Not Found' });
    }
    
    const indexPath = join(__dirname, '../frontend/dist/index.html');
    const html = await readFile(indexPath, 'utf-8');
    return reply.type('text/html').send(html);
  });
}

// ============ DATABASE MIGRATION ============
// Run migrations on startup
try {
  await import('./db/migrate.js');
  console.log('✅ Database migrations completed');
} catch (err) {
  console.error('❌ Database migration failed:', err);
  process.exit(1);
}

// ============ TRASH RETENTION ============
const TRASH_RETENTION_DAYS = parseInt(process.env.TRASH_RETENTION_DAYS || '30', 10);
const TRASH_PURGE_INTERVAL_HOURS = parseInt(process.env.TRASH_PURGE_INTERVAL_HOURS || '24', 10);

async function purgeExpiredTrash() {
  try {
    const res = await purgeTrashedOlderThanDays({
      db,
      schema,
      deleteFile,
      days: TRASH_RETENTION_DAYS,
    });
    if (res.deletedCount > 0) {
      console.log(
        `🧹 Purged ${res.deletedCount} trashed item(s) older than ${TRASH_RETENTION_DAYS}d (reclaimed ${res.reclaimedBytes} bytes)`
      );
    }
  } catch (err) {
    console.error('❌ Trash retention purge failed:', err);
  }
}

// Run once on startup (after migrations)
await purgeExpiredTrash();

// ============ START SERVER ============
const PORT = parseInt(process.env.PORT || '3000');
// In development, listen on localhost; in production, listen on all interfaces
const HOST = process.env.HOST || (isDev ? 'localhost' : '0.0.0.0');

try {
  await app.listen({ port: PORT, host: HOST });
  console.log(`🚀 SecureVault API running on http://${HOST}:${PORT}`);

  // Periodic trash purge
  const intervalMs = Math.max(1, TRASH_PURGE_INTERVAL_HOURS) * 60 * 60 * 1000;
  setInterval(purgeExpiredTrash, intervalMs).unref?.();
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

export default app;
