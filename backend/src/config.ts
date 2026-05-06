import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.string().default('info'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().optional(),
  DATABASE_URL: z.string().default('./data/securevault.db'),
  STORAGE_PATH: z.string().default('./uploads'),
  STORAGE_CONFIG_PATH: z.string().default('./config/storage.json'),
  CORS_ORIGIN: z.string().optional(),
  /** When set (e.g. https://vault.example.com), QR and device-link URLs use this instead of Host / X-Forwarded-* headers. */
  PUBLIC_APP_URL: z.preprocess(
    (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
    z.string().url().optional()
  ),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  MALWAREBAZAAR_API_KEY: z.string().optional(),
  TRASH_RETENTION_DAYS: z.coerce.number().int().min(1).default(30),
  TRASH_PURGE_INTERVAL_HOURS: z.coerce.number().int().min(1).default(24),
  /** 0 = never delete audit_logs rows. Otherwise delete rows older than this many days (same schedule as trash purge). */
  AUDIT_LOG_RETENTION_DAYS: z.coerce.number().int().min(0).default(0),
  /**
   * Session cookie SameSite. `lax` is a good default; use `strict` for stronger CSRF resistance.
   * `none` requires HTTPS (Secure cookies).
   */
  SESSION_COOKIE_SAMESITE: z.enum(['lax', 'strict', 'none']).default('lax'),
  /** `auto`: Secure cookie flag when the request is HTTPS (or X-Forwarded-Proto: https). */
  SESSION_COOKIE_SECURE: z.enum(['auto', 'true', 'false']).default('auto'),
  /** Also accept Authorization: Bearer (not recommended for browser clients; for API scripts/tests). */
  LEGACY_BEARER_AUTH: z.coerce.boolean().default(false),
  /** If true, invalidate session when client IP or User-Agent drifts from login values (can affect mobile networks). */
  SESSION_BIND_IP_UA: z.coerce.boolean().default(false),
  /** When SESSION_BIND_IP_UA: allow same IPv4 /24 as the login IP (reduces false positives on CGNAT). */
  SESSION_BIND_IPV4_SUBNET: z.coerce.boolean().default(true),
  /** Issue a new session token on the cookie at most every N hours (0 = disable). Mitigates stolen-token replay. */
  SESSION_ROTATE_HOURS: z.coerce.number().min(0).default(24),
  /** Send Strict-Transport-Security only when you serve real users over HTTPS end-to-end. */
  ENABLE_HSTS: z.coerce.boolean().default(false),
  HSTS_MAX_AGE_SECONDS: z.coerce.number().int().min(0).default(15552000),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;
export type Config = z.infer<typeof envSchema>;
