import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import multipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { readFile } from 'fs/promises';

import { authRoutes } from './routes/auth.js';
import { fileRoutes } from './routes/files.js';
import { shareRoutes } from './routes/share.js';
import { adminRoutes } from './routes/admin.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const isDev = process.env.NODE_ENV !== 'production';

const app = Fastify({
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
      connectSrc: ["'self'"],
      workerSrc: ["'self'", 'blob:'],
      upgradeInsecureRequests: null, // Disable HTTPS upgrade for HTTP-only deployments
    },
  },
  hsts: false, // Disable HSTS for HTTP deployments
});

// Rate limiting
await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (request) => request.ip,
});

// Multipart (file uploads)
await app.register(multipart, {
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB max file size
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

// ============ START SERVER ============
const PORT = parseInt(process.env.PORT || '3000');
const HOST = process.env.HOST || '0.0.0.0';

try {
  await app.listen({ port: PORT, host: HOST });
  console.log(`🚀 SecureVault API running on http://${HOST}:${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

export default app;
