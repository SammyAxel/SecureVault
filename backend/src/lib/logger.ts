import pino from 'pino';

const isDev = process.env.NODE_ENV !== 'production';

/** Shared logger for modules without a Fastify request (storage, external scans, migrations). */
export const libLogger = pino({
  level: process.env.LOG_LEVEL || (isDev ? 'debug' : 'info'),
  ...(isDev
    ? {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true },
        },
      }
    : {}),
});
