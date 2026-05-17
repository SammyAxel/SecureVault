import { createSignal, onMount, onCleanup, Show } from 'solid-js';
import { ROUTES } from '../lib/routes';
import { themeMode, switchTheme, type ThemeMode } from '../lib/theme';

const DROPDOWN_DURATION_MS = 200;

interface ProfileSectionProps {
  user: { username: string; displayName?: string; avatar?: string };
  isProfilePage: boolean;
  onLeaveProfile: () => void;
  onNavigate: (path: string) => void;
  onLogout: () => void;
}

function SunIcon() {
  return (
    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
        d="M12 3v1m0 16v1m8.66-13H20m-16 0H2.34M18.36 5.64l-.7.7M6.34 17.66l-.7.7M18.36 18.36l-.7-.7M6.34 6.34l-.7-.7M12 8a4 4 0 100 8 4 4 0 000-8z" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
        d="M21 12.79A9 9 0 1111.21 3a7 7 0 009.79 9.79z" />
    </svg>
  );
}

function MonitorIcon() {
  return (
    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
        d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
  );
}

const THEME_OPTIONS: { mode: ThemeMode; label: string; icon: () => import('solid-js').JSX.Element }[] = [
  { mode: 'light',  label: 'Light',  icon: SunIcon  },
  { mode: 'dark',   label: 'Dark',   icon: MoonIcon },
  { mode: 'system', label: 'System', icon: MonitorIcon },
];

export default function ProfileSection(props: ProfileSectionProps) {
  const [open, setOpen] = createSignal(false);
  const [closing, setClosing] = createSignal(false);
  let closeTimeout: ReturnType<typeof setTimeout> | undefined;
  let containerRef: HTMLDivElement | undefined;

  const closeDropdown = () => {
    if (!open()) return;
    setOpen(false);
    setClosing(true);
    if (closeTimeout) clearTimeout(closeTimeout);
    closeTimeout = setTimeout(() => setClosing(false), DROPDOWN_DURATION_MS);
  };

  const handleClickOutside = (e: MouseEvent) => {
    if (containerRef && !containerRef.contains(e.target as Node)) closeDropdown();
  };

  onMount(() => {
    document.addEventListener('click', handleClickOutside);
    onCleanup(() => {
      document.removeEventListener('click', handleClickOutside);
      if (closeTimeout) clearTimeout(closeTimeout);
    });
  });

  const visible = () => open() || closing();

  const themeButtonClass = (mode: ThemeMode) =>
    `flex-1 flex flex-col items-center gap-1 py-2 rounded-lg text-xs font-medium transition-all duration-150 ${
      themeMode() === mode
        ? 'bg-primary-600/20 text-primary-400 ring-1 ring-primary-500/30'
        : 'text-gray-400 hover:bg-gray-700/60 hover:text-gray-200'
    }`;

  return (
    <div class="relative" ref={containerRef}>
      <button
        type="button"
        onClick={() => (open() ? closeDropdown() : setOpen(true))}
        class={`flex items-center gap-2 p-2 sm:px-3 sm:py-1.5 rounded-lg transition-colors duration-200 touch-target sm:min-h-0 ${
          props.isProfilePage ? 'bg-primary-600 text-white' : 'hover:bg-gray-700 text-gray-300'
        }`}
        title={props.user.displayName || props.user.username}
        aria-label="Account menu"
        aria-haspopup="menu"
        aria-expanded={visible()}
      >
        <div class="w-8 h-8 rounded-full bg-gray-600 flex items-center justify-center overflow-hidden shrink-0 ring-2 ring-primary-500/20">
          <Show when={props.user.avatar} fallback={
            <span class="text-sm font-semibold text-gray-200">
              {props.user.username?.charAt(0).toUpperCase()}
            </span>
          }>
            <img src={props.user.avatar} alt="Avatar" class="w-full h-full object-cover" />
          </Show>
        </div>
        <span class="text-gray-300 max-w-[100px] sm:max-w-[120px] truncate hidden sm:inline text-sm font-medium">
          {props.user.displayName || props.user.username}
        </span>
        <svg
          class={`w-3.5 h-3.5 text-gray-500 shrink-0 transition-transform duration-200 ${visible() ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" viewBox="0 0 24 24"
        >
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <Show when={visible()}>
        <div
          class={`absolute right-0 top-full mt-2 w-64 max-w-[calc(100vw-1.5rem)] rounded-xl bg-gray-800 border border-gray-700 shadow-vault-float py-1.5 z-50 ${
            closing() ? 'animate-dropdown-out' : 'animate-dropdown-in'
          }`}
          role="menu"
        >
          {/* User header */}
          <div class="px-3 py-2.5 border-b border-gray-700/60">
            <div class="flex items-center gap-2.5">
              <div class="w-9 h-9 rounded-full bg-gray-600 flex items-center justify-center overflow-hidden shrink-0 ring-2 ring-primary-500/20">
                <Show when={props.user.avatar} fallback={
                  <span class="text-sm font-semibold text-gray-200">
                    {props.user.username?.charAt(0).toUpperCase()}
                  </span>
                }>
                  <img src={props.user.avatar} alt="" class="w-full h-full object-cover" />
                </Show>
              </div>
              <div class="min-w-0">
                <p class="text-sm font-semibold text-white truncate">
                  {props.user.displayName || props.user.username}
                </p>
                <p class="text-xs text-gray-500 truncate">@{props.user.username}</p>
              </div>
            </div>
          </div>

          {/* Profile settings */}
          <div class="pt-1">
            <button
              type="button"
              onClick={() => {
                if (props.isProfilePage) props.onLeaveProfile();
                else props.onNavigate(ROUTES.profile);
                closeDropdown();
              }}
              class="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-gray-700/60 hover:text-white flex items-center gap-2.5 transition-colors duration-150 rounded-lg mx-1"
              style="width: calc(100% - 8px)"
              role="menuitem"
            >
              <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
              </svg>
              {props.isProfilePage ? 'Back to Drive' : 'Profile Settings'}
            </button>
          </div>

          {/* Appearance toggle */}
          <div class="px-3 pt-2 pb-1 mt-1 border-t border-gray-700/60">
            <p class="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">Appearance</p>
            <div class="flex items-center gap-1.5">
              {THEME_OPTIONS.map(({ mode, label, icon: Icon }) => (
                <button
                  type="button"
                  onClick={() => switchTheme(mode)}
                  class={themeButtonClass(mode)}
                  title={`${label} theme`}
                  aria-pressed={themeMode() === mode}
                >
                  <Icon />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Log out */}
          <div class="pt-1 mt-1 border-t border-gray-700/60">
            <button
              type="button"
              onClick={() => { props.onLogout(); closeDropdown(); }}
              class="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-red-500/10 flex items-center gap-2.5 transition-colors duration-150 rounded-lg mx-1"
              style="width: calc(100% - 8px)"
              role="menuitem"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1z" />
              </svg>
              Sign Out
            </button>
          </div>
        </div>
      </Show>
    </div>
  );
}
