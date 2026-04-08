import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import multipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { readFile } from 'fs/promises';
import { ZodError } from 'zod';

import { config } from './config.js';
import { getClientIp } from './lib/clientIp.js';
import { db, schema } from './db/index.js';
import { deleteFile } from './lib/storage.js';
import { getTrashRetentionDays, purgeTrashedOlderThanDays } from './lib/trashRetention.js';
import { authRoutes } from './routes/auth.js';
import { fileRoutes } from './routes/files.js';
import { shareRoutes } from './routes/share.js';
import { adminRoutes } from './routes/admin.js';
import notificationRoutes from './routes/notifications.js';
import { trustedDevicesRoutes } from './routes/trustedDevices.js';
import { auditRoutes } from './routes/audit.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const isDev = config.NODE_ENV !== 'production';

const app = Fastify({
  requestTimeout: 10 * 60 * 1000,
  bodyLimit: 500 * 1024 * 1024,
  logger: isDev
    ? {
        level: config.LOG_LEVEL,
        transport: { target: 'pino-pretty', options: { colorize: true } },
      }
    : { level: config.LOG_LEVEL },
});

// ============ GLOBAL ERROR HANDLER ============
app.setErrorHandler((error, request, reply) => {
  if (error instanceof ZodError) {
    return reply.status(400).send({
      ok: false,
      msg: 'Validation error',
      errors: error.flatten().fieldErrors,
    });
  }

  if (error.statusCode && error.statusCode < 500) {
    return reply.status(error.statusCode).send({
      ok: false,
      msg: error.message || 'Request error',
    });
  }

  request.log.error(error);
  return reply.status(500).send({
    ok: false,
    msg: isDev ? error.message : 'Internal server error',
  });
});

// ============ PLUGINS ============

// CORS — explicit origin in production, permissive in dev
await app.register(cors, {
  origin: config.CORS_ORIGIN
    ? config.CORS_ORIGIN.split(',').map((o) => o.trim())
    : isDev
      ? true
      : false,
  credentials: true,
});

// Security headers — no unsafe-eval; unsafe-inline kept for Vite/Solid HMR styles
await app.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      mediaSrc: ["'self'", 'blob:'],
      objectSrc: ["'self'", 'blob:'],
      frameSrc: ["'self'", 'blob:'],
      connectSrc: ["'self'", 'blob:'],
      workerSrc: ["'self'", 'blob:'],
      upgradeInsecureRequests: null,
    },
  },
  hsts: false,
});

// Global rate limit
await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (request) => getClientIp(request),
});

// Stricter rate limit on auth endpoints
await app.register(async function authRateLimitPlugin(instance) {
  await instance.register(rateLimit, {
    max: 10,
    timeWindow: '1 minute',
    keyGenerator: (request) => getClientIp(request),
  });

  instance.addHook('onRoute', (routeOptions) => {
    const authPaths = [
      '/api/auth/challenge',
      '/api/auth/verify',
      '/api/auth/2fa/verify',
      '/api/auth/device-link/challenge',
      '/api/auth/device-link/verify',
    ];
    if (routeOptions.url && authPaths.includes(routeOptions.url)) {
      // Route-level config is handled by the encapsulated plugin
    }
  });
}, { prefix: '' });

// Multipart (file uploads)
await app.register(multipart, {
  limits: { fileSize: 500 * 1024 * 1024 },
});

// Serve static frontend files in production
if (config.NODE_ENV === 'production') {
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
await app.register(auditRoutes);

app.get('/api/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));

// SPA fallback
if (config.NODE_ENV === 'production') {
  app.setNotFoundHandler(async (request, reply) => {
    if (request.url.startsWith('/api/')) {
      return reply.status(404).send({ ok: false, msg: 'Not found' });
    }
    const indexPath = join(__dirname, '../frontend/dist/index.html');
    const html = await readFile(indexPath, 'utf-8');
    return reply.type('text/html').send(html);
  });
}

// ============ DATABASE MIGRATION ============
try {
  await import('./db/migrate.js');
  app.log.info('Database migrations completed');
} catch (err) {
  app.log.error(err, 'Database migration failed');
  process.exit(1);
}

// ============ TRASH RETENTION ============
const TRASH_RETENTION_DAYS = getTrashRetentionDays();

async function purgeExpiredTrash() {
  try {
    const res = await purgeTrashedOlderThanDays({
      db, schema, deleteFile, days: TRASH_RETENTION_DAYS,
    });
    if (res.deletedCount > 0) {
      app.log.info(
        { deletedCount: res.deletedCount, reclaimedBytes: res.reclaimedBytes, days: TRASH_RETENTION_DAYS },
        'Trash retention purge completed'
      );
    }
  } catch (err) {
    app.log.error(err, 'Trash retention purge failed');
  }
}

await purgeExpiredTrash();

// ============ START SERVER ============
const HOST = config.HOST || (isDev ? 'localhost' : '0.0.0.0');

try {
  await app.listen({ port: config.PORT, host: HOST });
  app.log.info(`SecureVault API running on http://${HOST}:${config.PORT}`);

  const intervalMs = Math.max(1, config.TRASH_PURGE_INTERVAL_HOURS) * 60 * 60 * 1000;
  setInterval(purgeExpiredTrash, intervalMs).unref?.();
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

export default app;
