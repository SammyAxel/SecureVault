/** Human-readable byte size for UI (call sites choose zero/unset display). */
export function formatSize(
  bytes: number | undefined | null,
  options?: {
    zero?: 'dash' | '0 B';
    unset?: 'dash' | '0 B';
    fractionDigits?: number | ((unitIndex: number) => number);
    withTb?: boolean;
  }
): string {
  const o = options ?? {};
  const unset = o.unset ?? '0 B';
  const zero = o.zero ?? '0 B';
  if (bytes === undefined || bytes === null) return unset === 'dash' ? '—' : '0 B';
  if (bytes === 0) return zero === 'dash' ? '—' : '0 B';

  const k = 1024;
  const sizes = o.withTb
    ? (['B', 'KB', 'MB', 'GB', 'TB'] as const)
    : (['B', 'KB', 'MB', 'GB'] as const);
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  const fd = o.fractionDigits;
  const decimals = typeof fd === 'function' ? fd(i) : (fd ?? 1);
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}
