/**
 * Display-only defaults; keep in sync with backend `TRASH_RETENTION_DAYS` when set.
 * Override at build time: `VITE_TRASH_RETENTION_DAYS=14 npm run build`
 */
const raw = import.meta.env.VITE_TRASH_RETENTION_DAYS;
const n = raw !== undefined && raw !== '' ? parseInt(String(raw), 10) : NaN;
export const TRASH_RETENTION_DAYS = Number.isFinite(n) && n > 0 ? n : 30;
