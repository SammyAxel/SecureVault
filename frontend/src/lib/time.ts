export type RelativeTimeStyle = 'short' | 'long';

function safeDate(input: string | number | Date): Date | null {
  const d = input instanceof Date ? input : new Date(input);
  // eslint-disable-next-line no-restricted-globals
  if (isNaN(d.getTime())) return null;
  return d;
}

function abs(n: number) {
  return Math.abs(n);
}

export function formatAbsolute(input: string | number | Date): string {
  const d = safeDate(input);
  if (!d) return '';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** Human-ish relative time (e.g. "2h ago", "yesterday", "in 3d"). */
export function formatRelative(input: string | number | Date, style: RelativeTimeStyle = 'short'): string {
  const d = safeDate(input);
  if (!d) return '';
  const diffMs = d.getTime() - Date.now();
  const future = diffMs > 0;
  const s = Math.round(abs(diffMs) / 1000);

  const fmt = (n: number, unit: 's' | 'm' | 'h' | 'd' | 'w' | 'mo' | 'y') => {
    if (style === 'long') {
      const label =
        unit === 's'
          ? 'second'
          : unit === 'm'
            ? 'minute'
            : unit === 'h'
              ? 'hour'
              : unit === 'd'
                ? 'day'
                : unit === 'w'
                  ? 'week'
                  : unit === 'mo'
                    ? 'month'
                    : 'year';
      const plural = n === 1 ? '' : 's';
      return future ? `in ${n} ${label}${plural}` : `${n} ${label}${plural} ago`;
    }
    return future ? `in ${n}${unit}` : `${n}${unit} ago`;
  };

  if (s < 10) return style === 'long' ? (future ? 'in a moment' : 'just now') : future ? 'soon' : 'now';
  if (s < 60) return fmt(s, 's');
  const m = Math.round(s / 60);
  if (m < 60) return fmt(m, 'm');
  const h = Math.round(m / 60);
  if (h < 24) return fmt(h, 'h');
  const dDays = Math.round(h / 24);
  if (!future && dDays === 1) return style === 'long' ? 'yesterday' : '1d ago';
  if (future && dDays === 1) return style === 'long' ? 'tomorrow' : 'in 1d';
  if (dDays < 7) return fmt(dDays, 'd');
  const w = Math.round(dDays / 7);
  if (w < 5) return fmt(w, 'w');
  const mo = Math.round(dDays / 30);
  if (mo < 12) return fmt(mo, 'mo');
  const y = Math.round(dDays / 365);
  return fmt(y, 'y');
}

