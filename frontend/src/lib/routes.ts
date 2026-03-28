/** App path constants and helpers — keep drive shell URLs in sync with the sidebar. */

export type DriveSection = 'home' | 'drive' | 'shared' | 'trash';

export const ROUTES = {
  home: '/home',
  homeSearch: '/home/search',
  drive: '/drive',
  driveSearch: '/drive/search',
  shared: '/shared',
  sharedSearch: '/shared/search',
  trash: '/trash',
  trashSearch: '/trash/search',
  admin: '/admin',
  profile: '/profile',
  login: '/login',
  register: '/register',
} as const;

/** Search results URL for the given sidebar tab (e.g. `/drive/search?q=`). */
export function pathForSectionSearch(section: DriveSection): string {
  switch (section) {
    case 'home':
      return ROUTES.homeSearch;
    case 'drive':
      return ROUTES.driveSearch;
    case 'shared':
      return ROUTES.sharedSearch;
    case 'trash':
      return ROUTES.trashSearch;
  }
}

export function isVaultSearchRoute(pathname: string): boolean {
  return (
    pathname === ROUTES.homeSearch ||
    pathname === ROUTES.driveSearch ||
    pathname === ROUTES.sharedSearch ||
    pathname === ROUTES.trashSearch
  );
}

export function driveSectionFromPath(pathname: string): DriveSection {
  if (
    pathname === '/' ||
    pathname === ROUTES.home ||
    pathname === ROUTES.homeSearch ||
    pathname === '/search'
  ) {
    return 'home';
  }
  if (
    pathname === ROUTES.drive ||
    pathname === ROUTES.driveSearch ||
    pathname.startsWith('/f/')
  ) {
    return 'drive';
  }
  if (pathname === ROUTES.shared || pathname === ROUTES.sharedSearch) return 'shared';
  if (pathname === ROUTES.trash || pathname === ROUTES.trashSearch) return 'trash';
  return 'home';
}

export function pathForDriveSection(section: DriveSection): string {
  switch (section) {
    case 'home':
      return ROUTES.home;
    case 'drive':
      return ROUTES.drive;
    case 'shared':
      return ROUTES.shared;
    case 'trash':
      return ROUTES.trash;
  }
}

/** Google-Drive-style global search query key in the URL. */
export const SEARCH_QUERY_KEY = 'q';

/** True for views that show the vault header search (synced to `?q=`). */
export function isDriveShellPath(pathname: string): boolean {
  if (pathname === ROUTES.admin || pathname === ROUTES.profile) return false;
  if (pathname === ROUTES.login || pathname === ROUTES.register) return false;
  if (pathname.startsWith('/share/')) return false;
  if (
    pathname === '/' ||
    pathname === ROUTES.home ||
    pathname === ROUTES.homeSearch ||
    pathname === '/search'
  ) {
    return true;
  }
  if (
    pathname === ROUTES.drive ||
    pathname === ROUTES.driveSearch ||
    pathname.startsWith('/f/')
  ) {
    return true;
  }
  if (pathname === ROUTES.shared || pathname === ROUTES.sharedSearch) return true;
  if (pathname === ROUTES.trash || pathname === ROUTES.trashSearch) return true;
  return false;
}

export function parseSearchQuery(search: string): string {
  const v = new URLSearchParams(search).get(SEARCH_QUERY_KEY);
  return v != null ? v : '';
}

/** Pathname + optional `?q=` (omits param when query is empty). */
export function pathWithSearch(pathname: string, q: string): string {
  const trimmed = q.trim();
  if (!trimmed) return pathname;
  const params = new URLSearchParams();
  params.set(SEARCH_QUERY_KEY, trimmed);
  return `${pathname}?${params.toString()}`;
}

/** Keep current `window` search params when changing pathname only (e.g. folder navigation). */
export function hrefWithCurrentSearch(pathname: string): string {
  const s = typeof window !== 'undefined' ? window.location.search : '';
  return s ? `${pathname}${s}` : pathname;
}

/** Paths that require an authenticated session (vault UI, not public share). */
export function isProtectedVaultPath(pathname: string): boolean {
  if (
    pathname === '/' ||
    pathname === ROUTES.home ||
    pathname === ROUTES.homeSearch ||
    pathname === '/search'
  ) {
    return true;
  }
  if (
    pathname === ROUTES.drive ||
    pathname === ROUTES.driveSearch ||
    pathname.startsWith('/f/')
  ) {
    return true;
  }
  if (pathname === ROUTES.shared || pathname === ROUTES.sharedSearch) return true;
  if (pathname === ROUTES.trash || pathname === ROUTES.trashSearch) return true;
  if (pathname === ROUTES.admin || pathname === ROUTES.profile) return true;
  return false;
}
