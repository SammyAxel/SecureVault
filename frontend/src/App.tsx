import {
  createSignal,
  Show,
  createEffect,
  createMemo,
  onMount,
  onCleanup,
  untrack,
  lazy,
  Suspense,
} from 'solid-js';
import { AuthProvider, useAuth } from './stores/auth.jsx';
import Login from './components/Login';
import DeviceLinkLogin from './components/DeviceLinkLogin';
import Register from './components/Register';
import Setup from './components/Setup';
import ToastContainer from './components/Toast';
import ConfirmModal from './components/ConfirmModal';
import KeyboardShortcutsModal from './components/KeyboardShortcutsModal';
import { initTheme } from './lib/theme';
import { initI18n } from './lib/i18n';
import { isTypingInField } from './lib/keyboardShortcuts';

const Dashboard = lazy(() => import('./components/dashboard/Dashboard'));
const Profile = lazy(() => import('./components/profile/Profile'));
const AdminDashboard = lazy(() => import('./components/admin/AdminDashboard'));
const PublicShare = lazy(() => import('./components/share/PublicShare'));
import Sidebar from './components/Sidebar';
import MobileNavDrawer from './components/MobileNavDrawer';
import ProfileSection from './components/ProfileDropdown';
import Home from './components/Home';
import DemoBanner from './components/DemoBanner';
import DemoTour, { shouldAutoStartTour } from './components/DemoTour';
import * as api from './lib/api';
import {
  ROUTES,
  driveSectionFromPath,
  pathForDriveSection,
  pathForSectionSearch,
  isProtectedVaultPath,
  isDriveShellPath,
  isVaultSearchRoute,
  pathWithSearch,
  parseSearchQuery,
  hrefWithCurrentSearch,
} from './lib/routes';
import { awaitMinElapsed, MIN_SETUP_WIZARD_MS, MIN_SEARCH_FEEDBACK_MS } from './lib/motion';
import { logger } from './lib/logger';
import { useRoute } from './lib/useRoute';
import { isSubtleCryptoAvailable, insecureWebCryptoMessage } from './lib/webCryptoSupport';

function LazyRouteFallback() {
  return (
    <div class="flex items-center justify-center min-h-[40vh] text-gray-400 animate-sv-rise">
      <div class="flex flex-col items-center gap-3">
        <div class="animate-spin rounded-full h-10 w-10 border-2 border-primary-500/30 border-t-primary-500" />
        <span class="text-sm">Loading…</span>
      </div>
    </div>
  );
}

function AppContent() {
  const { user, isLoading, logout } = useAuth();
  let mobileSearchField: HTMLInputElement | undefined;
  let desktopSearchField: HTMLInputElement | undefined;
  const [showRegister, setShowRegister] = createSignal(false);
  const [needsSetup, setNeedsSetup] = createSignal(false);
  const [checkingSetup, setCheckingSetup] = createSignal(true);
  const { path, locationSearch, navigate, replacePath } = useRoute();
  const initialVaultQ =
    typeof window !== 'undefined' ? parseSearchQuery(window.location.search) : '';
  const [searchApplied, setSearchApplied] = createSignal(initialVaultQ);
  const [searchDraft, setSearchDraft] = createSignal(initialVaultQ);
  const [searchLoading, setSearchLoading] = createSignal(false);
  const [routeContentOpacity, setRouteContentOpacity] = createSignal(1);
  const [routeEntering, setRouteEntering] = createSignal(false);
  const [mobileNavOpen, setMobileNavOpen] = createSignal(false);
  const [mobileSearchOpen, setMobileSearchOpen] = createSignal(false);
  const [demoMode, setDemoMode] = createSignal(false);
  const [demoUsername, setDemoUsername] = createSignal<string | undefined>();
  const [tourActive, setTourActive] = createSignal(false);
  const [shortcutsOpen, setShortcutsOpen] = createSignal(false);

  const driveShellOpen = () => !!user() && !isAdminPage() && !isProfilePage();

  const focusVaultSearch = () => {
    if (typeof window === 'undefined') return;
    if (window.matchMedia('(min-width: 768px)').matches) {
      queueMicrotask(() => desktopSearchField?.focus());
    } else {
      setMobileSearchOpen(true);
    }
  };

  createEffect(() => {
    if (!mobileSearchOpen()) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileSearchOpen(false);
    };
    document.addEventListener('keydown', onKey);
    onCleanup(() => document.removeEventListener('keydown', onKey));
  });

  createEffect(() => {
    if (!mobileSearchOpen()) return;
    const id = window.requestAnimationFrame(() => mobileSearchField?.focus());
    onCleanup(() => cancelAnimationFrame(id));
  });

  const clearVaultSearch = () => {
    setSearchDraft('');
    setSearchApplied('');
    setSearchLoading(false);
    const p = path();
    if (isVaultSearchRoute(p)) {
      replacePath(pathForDriveSection(driveSectionFromPath(p)));
      return;
    }
    if (isDriveShellPath(p)) replacePath(pathWithSearch(p, ''));
  };

  const commitVaultSearch = () => {
    const p = path();
    if (!isDriveShellPath(p)) return;
    const raw = searchDraft().trim();
    setSearchApplied(raw);
    setSearchLoading(true);
    const section = driveSectionFromPath(p);
    const next = raw
      ? pathWithSearch(pathForSectionSearch(section), raw)
      : isVaultSearchRoute(p)
        ? pathForDriveSection(section)
        : pathWithSearch(p, '');
    const cur = `${window.location.pathname}${window.location.search}`;
    if (next !== cur) replacePath(next);
    setMobileSearchOpen(false);
    requestAnimationFrame(() => {
      window.setTimeout(() => setSearchLoading(false), MIN_SEARCH_FEEDBACK_MS);
    });
  };

  const activeDriveSection = createMemo(() => driveSectionFromPath(path()));

  let routeTransitionPrev = '';
  createEffect(() => {
    const p = path();
    if (routeTransitionPrev !== '' && p !== routeTransitionPrev) {
      // Instantly hide + shift down; new content already mounted by reactivity
      setRouteContentOpacity(0);
      setRouteEntering(true);
      // Short pause so browser paints opacity=0 before we start the fade-in
      const t = window.setTimeout(() => {
        setRouteContentOpacity(1);
        setRouteEntering(false);
      }, 60);
      onCleanup(() => clearTimeout(t));
    }
    routeTransitionPrev = p;
  });

  // Check if we're on admin page
  const isAdminPage = () => path() === ROUTES.admin;

  // Check if we're on profile page
  const isProfilePage = () => path() === ROUTES.profile;

  // Extract UID from /f/:uid path (folder/file deep link)
  const getUIDFromPath = () => {
    const match = path().match(/^\/f\/([^/?#]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  };

  // Canonical `/` and legacy `?q=` on base paths → `/…/search?q=` per tab; old `/search` → `/home/search`
  createEffect(() => {
    if (checkingSetup() || needsSetup()) return;
    if (!user()) return;
    if (path() === '/') {
      const q = parseSearchQuery(locationSearch()).trim();
      replacePath(q ? pathWithSearch(ROUTES.homeSearch, q) : ROUTES.home);
      return;
    }
    const q = parseSearchQuery(locationSearch()).trim();
    if (!q) return;
    const p = path();
    if (p === '/search') {
      replacePath(pathWithSearch(ROUTES.homeSearch, q));
      return;
    }
    const legacy: [string, string][] = [
      [ROUTES.home, ROUTES.homeSearch],
      [ROUTES.drive, ROUTES.driveSearch],
      [ROUTES.shared, ROUTES.sharedSearch],
      [ROUTES.trash, ROUTES.trashSearch],
    ];
    for (const [base, searchPath] of legacy) {
      if (p === base) {
        replacePath(pathWithSearch(searchPath, q));
        return;
      }
    }
    if (/^\/f\/[^/?#]+$/.test(p)) {
      replacePath(pathWithSearch(ROUTES.driveSearch, q));
    }
  });

  // URL `?q=` → applied query + input draft (back/forward, direct links). Not subscribed to draft while typing.
  createEffect(() => {
    if (checkingSetup() || needsSetup()) return;
    if (!user()) return;
    const p = path();
    const loc = locationSearch();
    if (!isDriveShellPath(p)) return;
    const q = parseSearchQuery(loc);
    const applied = untrack(() => searchApplied());
    if (q !== applied) {
      setSearchApplied(q);
      setSearchDraft(q);
    }
  });

  // Sync path with login/register view: /login -> Login, /register -> Register
  createEffect(() => {
    const p = path();
    if (p === ROUTES.login || p === ROUTES.loginLink) setShowRegister(false);
    else if (p === ROUTES.register) setShowRegister(true);
  });

  // After login (or when already logged in on auth pages), redirect to home so URL is proper
  createEffect(() => {
    if (!user()) return;
    const p = path();
    if (p === ROUTES.login || p === ROUTES.register || p === ROUTES.loginLink) navigate(ROUTES.home);
  });

  // Auto-start demo tour on first visit (after login completes and we're on home)
  createEffect(() => {
    if (!demoMode() || !user() || isLoading()) return;
    if (path() === ROUTES.home && shouldAutoStartTour()) {
      setTimeout(() => setTourActive(true), 600);
    }
  });

  // When not logged in and on a protected path, redirect to /login (after session restore finishes)
  createEffect(() => {
    if (checkingSetup() || needsSetup()) return;
    if (isLoading()) return;
    if (user()) return;
    const p = path();
    if (isProtectedVaultPath(p)) {
      navigate(ROUTES.login);
    }
  });

  // Check setup status and register auth:logout listener on mount
  onMount(() => {
    initI18n();
    initTheme();
    const handleLogout = () => navigate(ROUTES.login);
    window.addEventListener('auth:logout', handleLogout);

    (async () => {
      const started = Date.now();
      try {
        const status = await api.checkSetupStatus();
        setNeedsSetup(status.needsSetup);
        if (status.demoMode) setDemoMode(true);
        if (status.demoUsername) setDemoUsername(status.demoUsername);
      } catch (err) {
        logger.error('Failed to check setup status:', err);
        setNeedsSetup(false);
      } finally {
        await awaitMinElapsed(started, MIN_SETUP_WIZARD_MS);
        setCheckingSetup(false);
      }
    })();

    const onGlobalShortcut = (e: KeyboardEvent) => {
      if (checkingSetup() || needsSetup() || !user()) return;

      if (shortcutsOpen()) {
        if (e.key === 'Escape') {
          e.preventDefault();
          setShortcutsOpen(false);
        }
        return;
      }

      if (!driveShellOpen()) return;
      if (isTypingInField(e.target)) return;

      if (e.key === '?' || (e.shiftKey && e.key === '/')) {
        e.preventDefault();
        setShortcutsOpen(true);
        return;
      }
      if (e.key === '/' && !e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        focusVaultSearch();
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        focusVaultSearch();
      }
    };
    document.addEventListener('keydown', onGlobalShortcut);

    return () => {
      window.removeEventListener('auth:logout', handleLogout);
      document.removeEventListener('keydown', onGlobalShortcut);
    };
  });

  return (
    <>
      <Show when={typeof window !== 'undefined' && !isSubtleCryptoAvailable()}>
        <div
          role="alert"
          class="bg-amber-900/90 border-b border-amber-700 text-amber-100 px-4 py-3 text-sm text-center leading-relaxed"
        >
          {insecureWebCryptoMessage()}
        </div>
      </Show>
      {/* Loading state */}
      <Show when={checkingSetup()}>
        <div class="min-h-screen bg-gray-900 flex items-center justify-center">
          <div class="text-center animate-sv-rise">
            <div class="animate-spin rounded-full h-12 w-12 border-2 border-primary-500/30 border-t-primary-500 mx-auto mb-4"></div>
            <p class="text-gray-400">Loading SecureVault...</p>
          </div>
        </div>
      </Show>

      {/* Setup wizard */}
      <Show when={!checkingSetup() && needsSetup()}>
        <Setup onComplete={() => setNeedsSetup(false)} />
      </Show>

      {/* Main app */}
      <Show when={!checkingSetup() && !needsSetup()}>
        <div class="min-h-screen bg-gray-900 animate-sv-rise">
          <Show when={demoMode() && !!user()}>
            <DemoBanner />
          </Show>

          {/* Header */}
          <header class="bg-gray-800 border-b border-gray-700">
            <div class="max-w-7xl mx-auto px-3 sm:px-4 py-3 sm:py-4 flex items-center justify-between gap-2 flex-wrap">
              <div class="flex items-center gap-1 sm:gap-2 min-w-0 shrink-0">
                <Show when={user() && !isAdminPage() && !isProfilePage()}>
                  <button
                    type="button"
                    class="lg:hidden p-2 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white touch-target"
                    onClick={() => setMobileNavOpen(true)}
                    aria-label="Open navigation menu"
                  >
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                    </svg>
                  </button>
                </Show>
              <div
                class="flex items-center gap-2 sm:gap-3 cursor-pointer min-w-0 shrink-0"
                data-demo-tour="logo"
                onClick={() => {
                  clearVaultSearch();
                  if (path() !== ROUTES.home) navigate(ROUTES.home);
                }}
              >
                <div class="w-9 h-9 sm:w-10 sm:h-10 bg-primary-600 rounded-lg flex items-center justify-center shrink-0">
                  <svg class="w-5 h-5 sm:w-6 sm:h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <h1 class="text-lg sm:text-xl font-bold text-white truncate">SecureVault</h1>
              </div>
              </div>

              <Show when={user()}>
                <Show when={!isAdminPage() && !isProfilePage()}>
                  <div class="hidden md:flex flex-1 min-w-[240px] max-w-xl mx-2">
                    <form
                      class="relative w-full flex items-center gap-2"
                      onSubmit={(e) => {
                        e.preventDefault();
                        commitVaultSearch();
                      }}
                      role="search"
                    >
                      <div class="relative flex-1 min-w-0">
                        <svg
                          class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                          aria-hidden
                        >
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                        <input
                          type="text"
                          name="q"
                          placeholder="Search in SecureVault…"
                          value={searchDraft()}
                          onInput={(e) => setSearchDraft(e.currentTarget.value)}
                          ref={(el) => {
                            desktopSearchField = el;
                          }}
                          class="w-full pl-10 pr-10 py-2 bg-gray-700/60 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                          autocomplete="off"
                        />
                        <Show when={searchDraft() || searchApplied()}>
                          <button
                            type="button"
                            onClick={() => clearVaultSearch()}
                            class="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-gray-400 hover:text-white"
                            title="Clear search"
                            aria-label="Clear search"
                          >
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                          </button>
                        </Show>
                      </div>
                      <Show when={searchLoading()}>
                        <div
                          class="shrink-0 w-9 h-9 flex items-center justify-center"
                          role="status"
                          aria-label="Searching"
                        >
                          <div class="animate-spin rounded-full h-6 w-6 border-2 border-primary-400 border-t-transparent" />
                        </div>
                      </Show>
                      <div aria-live="polite" class="sr-only">
                        {searchLoading() ? 'Searching...' : searchApplied() ? `Showing results for "${searchApplied()}"` : ''}
                      </div>
                    </form>
                  </div>
                </Show>

                <div class="flex items-center gap-2 sm:gap-4 shrink-0">
                  <Show when={demoMode()}>
                    <button
                      type="button"
                      onClick={() => setTourActive(true)}
                      class="p-2 sm:px-3 sm:py-1.5 rounded-lg text-sm flex items-center gap-2 touch-target sm:min-h-0 bg-gray-700 text-gray-300 hover:bg-gray-600"
                      title="Start guided tour"
                      aria-label="Start guided tour"
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span class="hidden sm:inline">Tour</span>
                    </button>
                  </Show>
                  <Show when={!isAdminPage() && !isProfilePage()}>
                    <button
                      type="button"
                      class="p-2 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white touch-target"
                      onClick={() => setShortcutsOpen(true)}
                      title="Keyboard shortcuts (?)"
                      aria-label="Keyboard shortcuts"
                    >
                      <svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.546-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                    </button>
                    <button
                      type="button"
                      class="md:hidden p-2 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white touch-target"
                      onClick={() => setMobileSearchOpen(true)}
                      aria-label="Open search"
                    >
                      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                      </svg>
                    </button>
                  </Show>
                  {/* Admin link: icon-only on small screens */}
                  <Show when={user()?.isAdmin}>
                    <button
                      type="button"
                      data-demo-tour="admin-btn"
                      onClick={() =>
                        isAdminPage() ? window.history.back() : navigate(ROUTES.admin)
                      }
                      class={`p-2 sm:px-3 sm:py-1.5 rounded-lg text-sm flex items-center gap-2 touch-target sm:min-h-0 ${
                        isAdminPage()
                          ? 'bg-primary-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                      title={isAdminPage() ? 'Exit Admin' : 'Admin'}
                      aria-label={isAdminPage() ? 'Exit admin' : 'Open admin dashboard'}
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                      <span class="hidden md:inline">{isAdminPage() ? 'Exit Admin' : 'Admin'}</span>
                    </button>
                  </Show>

                  {/* Profile section (Discord-style) with dropdown */}
                  <span data-demo-tour="profile-btn">
                  <ProfileSection
                    user={user()!}
                    isProfilePage={isProfilePage()}
                    onLeaveProfile={() => window.history.back()}
                    onNavigate={navigate}
                    onLogout={logout}
                  />
                  </span>
                </div>
              </Show>
            </div>
          </header>

          <MobileNavDrawer
            open={mobileNavOpen() && driveShellOpen()}
            onClose={() => setMobileNavOpen(false)}
            active={activeDriveSection()}
            onNavigate={(section) => {
              clearVaultSearch();
              navigate(pathForDriveSection(section));
            }}
          />

          <Show when={mobileSearchOpen() && driveShellOpen()}>
            <div
              class="fixed inset-0 z-[70] md:hidden flex flex-col"
              role="dialog"
              aria-modal="true"
              aria-label="Search vault"
            >
              <button
                type="button"
                class="absolute inset-0 bg-black/60 border-0 w-full h-full cursor-default"
                onClick={() => setMobileSearchOpen(false)}
                aria-label="Close search"
              />
              <div class="relative mt-[max(12px,env(safe-area-inset-top))] mx-3 rounded-xl bg-gray-800 border border-gray-700 shadow-vault-float overflow-hidden">
                <div class="flex items-center justify-between px-3 py-2 border-b border-gray-700">
                  <span class="text-sm font-medium text-white">Search</span>
                  <button
                    type="button"
                    onClick={() => setMobileSearchOpen(false)}
                    class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700"
                    aria-label="Close search"
                  >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
                <form
                  class="p-3 flex flex-col gap-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    commitVaultSearch();
                  }}
                  role="search"
                >
                  <input
                    type="text"
                    name="q"
                    placeholder="Search in SecureVault…"
                    value={searchDraft()}
                    onInput={(e) => setSearchDraft(e.currentTarget.value)}
                    ref={(el) => {
                      mobileSearchField = el;
                    }}
                    class="w-full px-3 py-2.5 bg-gray-700/60 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                    autocomplete="off"
                  />
                  <div class="flex gap-2 justify-end">
                    <button
                      type="button"
                      onClick={() => {
                        clearVaultSearch();
                        setMobileSearchOpen(false);
                      }}
                      class="px-3 py-2 text-sm text-gray-300 hover:text-white"
                    >
                      Clear
                    </button>
                    <button
                      type="submit"
                      class="px-4 py-2 text-sm rounded-lg bg-primary-600 hover:bg-primary-700 text-white"
                    >
                      Search
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </Show>

          {/* Main Content */}
          <main class="max-w-7xl mx-auto px-3 sm:px-4 py-4 sm:py-8">
            <Show when={isLoading()}>
              <div class="flex items-center justify-center h-64 animate-sv-rise">
                <div class="animate-spin rounded-full h-12 w-12 border-2 border-primary-500/30 border-t-primary-500"></div>
              </div>
            </Show>

            <Show when={!isLoading()}>
              <div
                class={`sv-route-shell${routeEntering() ? ' sv-route-shell-entering' : ''}`}
                style={{ opacity: String(routeContentOpacity()) }}
              >
              <Show
                when={user()}
                fallback={
                  <Show
                    when={path() === ROUTES.loginLink}
                    fallback={
                      <Show
                        when={showRegister()}
                        fallback={
                          <Login
                            onSwitchToRegister={() => navigate(ROUTES.register)}
                            onGotoQrLogin={() => navigate(ROUTES.loginLink)}
                            isDemoMode={demoMode()}
                            demoUsername={demoUsername()}
                          />
                        }
                      >
                        <Register onSwitchToLogin={() => navigate(ROUTES.login)} />
                      </Show>
                    }
                  >
                    <DeviceLinkLogin
                      navigate={navigate}
                      onSwitchToNormalLogin={() => navigate(ROUTES.login)}
                      onSwitchToRegister={() => navigate(ROUTES.register)}
                    />
                  </Show>
                }
              >
                {/* Profile Page */}
                <Show when={isProfilePage()}>
                  <Suspense fallback={<LazyRouteFallback />}>
                    <Profile onBack={() => window.history.back()} />
                  </Suspense>
                </Show>

                {/* Admin Dashboard */}
                <Show when={isAdminPage() && user()?.isAdmin && !isProfilePage()}>
                  <Suspense fallback={<LazyRouteFallback />}>
                    <AdminDashboard />
                  </Suspense>
                </Show>

                {/* Drive shell (Sidebar + content) */}
                <Show when={!isAdminPage() && !isProfilePage()}>
                  <div class="flex gap-6">
                    <Sidebar
                      active={activeDriveSection()}
                      onNavigate={(section) => {
                        clearVaultSearch();
                        navigate(pathForDriveSection(section));
                      }}
                    />
                    <div class="flex-1 min-w-0">
                      <Show
                        when={activeDriveSection() === 'home'}
                        fallback={
                          <Suspense fallback={<LazyRouteFallback />}>
                            <Dashboard
                              navigate={navigate}
                              replaceHref={replacePath}
                              uid={getUIDFromPath()}
                              section={activeDriveSection() as 'drive' | 'shared' | 'trash'}
                              onRequestNavigateRoot={() =>
                                navigate(hrefWithCurrentSearch(ROUTES.drive))
                              }
                              globalSearch={searchApplied()}
                              clearVaultSearch={clearVaultSearch}
                              searchLoading={searchLoading()}
                            />
                          </Suspense>
                        }
                      >
                        <Home
                          search={searchApplied()}
                          searchLoading={searchLoading()}
                          onGoToDrive={() => navigate(hrefWithCurrentSearch(ROUTES.drive))}
                          onOpenFolder={(_folderId, _folderName, uid) => {
                            navigate(hrefWithCurrentSearch(uid ? `/f/${uid}` : ROUTES.drive));
                          }}
                          onOpenFile={(file) => {
                            if (file.uid) {
                              navigate(hrefWithCurrentSearch(`/f/${file.uid}`));
                            }
                          }}
                          onDownloadFile={() => {}}
                        />
                      </Show>
                    </div>
                  </div>
                </Show>
              </Show>
              </div>
            </Show>
          </main>

          <Show when={demoMode()}>
            <DemoTour active={tourActive()} onClose={() => setTourActive(false)} />
          </Show>
          <KeyboardShortcutsModal open={shortcutsOpen()} onClose={() => setShortcutsOpen(false)} />
        </div>
      </Show>
    </>
  );
}

export default function App() {
  // Check for public routes that don't need auth
  const isShareRoute = () => window.location.pathname.startsWith('/share/');
  
  // Render public share page
  if (isShareRoute()) {
    return (
      <Suspense fallback={<LazyRouteFallback />}>
        <PublicShare />
      </Suspense>
    );
  }
  
  return (
    <AuthProvider>
      <AppContent />
      <ToastContainer />
      <ConfirmModal />
    </AuthProvider>
  );
}
