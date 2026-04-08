export type ThemeMode = 'dark' | 'light' | 'system';

const STORAGE_KEY = 'sv_theme_mode';

export function getStoredThemeMode(): ThemeMode {
  if (typeof window === 'undefined') return 'system';
  const raw = localStorage.getItem(STORAGE_KEY);
  if (raw === 'dark' || raw === 'light' || raw === 'system') return raw;
  return 'system';
}

export function setStoredThemeMode(mode: ThemeMode): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, mode);
}

export function resolvedTheme(mode: ThemeMode): Exclude<ThemeMode, 'system'> {
  if (mode !== 'system') return mode;
  const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)')?.matches;
  return prefersDark ? 'dark' : 'light';
}

export function applyTheme(mode: ThemeMode): void {
  if (typeof document === 'undefined') return;
  const theme = resolvedTheme(mode);
  document.documentElement.setAttribute('data-theme', theme);
  // Helps form controls / scrollbars match theme.
  document.documentElement.style.colorScheme = theme;
}

export function initTheme(): void {
  if (typeof window === 'undefined') return;
  const mode = getStoredThemeMode();
  applyTheme(mode);

  // Re-apply when system theme changes (only in system mode).
  const mql = window.matchMedia?.('(prefers-color-scheme: dark)');
  const handler = () => {
    if (getStoredThemeMode() === 'system') applyTheme('system');
  };
  try {
    mql?.addEventListener('change', handler);
  } catch {
    // Safari fallback
    (mql as unknown as { addListener?: (cb: () => void) => void } | null)?.addListener?.(handler);
  }
}

