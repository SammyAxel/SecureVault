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
  VIRUSTOTAL_API_KEY: z.string().optional(),
  MALWAREBAZAAR_API_KEY: z.string().optional(),
  TRASH_RETENTION_DAYS: z.coerce.number().int().min(1).default(30),
  TRASH_PURGE_INTERVAL_HOURS: z.coerce.number().int().min(1).default(24),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;
export type Config = z.infer<typeof envSchema>;
