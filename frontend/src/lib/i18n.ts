export type Locale = 'en' | 'ms';

const STORAGE_KEY = 'sv_locale';

const DICT: Record<Locale, Record<string, string>> = {
  en: {
    'profile.title': 'Profile Settings',
    'profile.theme': 'Theme',
    'profile.language': 'Language',
    'theme.system': 'System',
    'theme.dark': 'Dark',
    'theme.light': 'Light',
    'language.en': 'English',
    'language.ms': 'Malay',
    'activity.title': 'Activity',
    'activity.empty': 'No activity yet.',
  },
  ms: {
    'profile.title': 'Tetapan Profil',
    'profile.theme': 'Tema',
    'profile.language': 'Bahasa',
    'theme.system': 'Sistem',
    'theme.dark': 'Gelap',
    'theme.light': 'Cerah',
    'language.en': 'Inggeris',
    'language.ms': 'Melayu',
    'activity.title': 'Aktiviti',
    'activity.empty': 'Tiada aktiviti lagi.',
  },
};

let currentLocale: Locale = 'en';

export function getStoredLocale(): Locale {
  if (typeof window === 'undefined') return 'en';
  const raw = localStorage.getItem(STORAGE_KEY);
  if (raw === 'en' || raw === 'ms') return raw;
  // default based on browser
  const nav = (navigator.language || 'en').toLowerCase();
  if (nav.startsWith('ms')) return 'ms';
  return 'en';
}

export function setStoredLocale(locale: Locale): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, locale);
  currentLocale = locale;
  window.dispatchEvent(new CustomEvent('sv:locale-changed', { detail: { locale } }));
}

export function initI18n(): void {
  currentLocale = getStoredLocale();
}

export function getLocale(): Locale {
  return currentLocale;
}

export function t(key: string): string {
  return DICT[currentLocale]?.[key] ?? DICT.en[key] ?? key;
}

