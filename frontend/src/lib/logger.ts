const dev = import.meta.env.DEV;

/** Development-only logging; production stays quiet (user-facing errors use toast). */
export const logger = {
  debug: (...args: unknown[]) => {
    if (dev) console.log(...args);
  },
  warn: (...args: unknown[]) => {
    if (dev) console.warn(...args);
  },
  error: (...args: unknown[]) => {
    if (dev) console.error(...args);
  },
};
