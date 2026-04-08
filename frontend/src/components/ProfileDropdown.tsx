import { createSignal, onMount, onCleanup, Show } from 'solid-js';
import { ROUTES } from '../lib/routes';

const DROPDOWN_DURATION_MS = 240;

interface ProfileSectionProps {
  user: { username: string; displayName?: string; avatar?: string };
  isProfilePage: boolean;
  onLeaveProfile: () => void;
  onNavigate: (path: string) => void;
  onLogout: () => void;
}

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
        <div class="w-8 h-8 rounded-full bg-gray-600 flex items-center justify-center overflow-hidden shrink-0">
          <Show when={props.user.avatar} fallback={
            <span class="text-sm font-medium text-gray-300">
              {props.user.username?.charAt(0).toUpperCase()}
            </span>
          }>
            <img src={props.user.avatar} alt="Avatar" class="w-full h-full object-cover" />
          </Show>
        </div>
        <span class="text-gray-300 max-w-[100px] sm:max-w-[120px] truncate hidden sm:inline">
          {props.user.displayName || props.user.username}
        </span>
        <svg
          class={`w-4 h-4 text-gray-400 shrink-0 transition-transform duration-200 ${visible() ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <Show when={visible()}>
        <div
          class={`absolute right-0 top-full mt-1 w-56 max-w-[calc(100vw-1.5rem)] rounded-lg bg-gray-800 border border-gray-700 shadow-xl py-1 z-50 ${closing() ? 'animate-dropdown-out' : 'animate-dropdown-in'}`}
          role="menu"
        >
          <div class="px-3 py-2 border-b border-gray-700">
            <div class="flex items-center gap-2">
              <div class="w-9 h-9 rounded-full bg-gray-600 flex items-center justify-center overflow-hidden shrink-0">
                <Show when={props.user.avatar} fallback={
                  <span class="text-sm font-medium text-gray-300">
                    {props.user.username?.charAt(0).toUpperCase()}
                  </span>
                }>
                  <img src={props.user.avatar} alt="" class="w-full h-full object-cover" />
                </Show>
              </div>
              <div class="min-w-0">
                <p class="text-sm font-medium text-white truncate">
                  {props.user.displayName || props.user.username}
                </p>
                <p class="text-xs text-gray-400 truncate">{props.user.username}</p>
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              if (props.isProfilePage) props.onLeaveProfile();
              else props.onNavigate(ROUTES.profile);
              closeDropdown();
            }}
            class="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 hover:text-white flex items-center gap-2 transition-colors duration-150"
            role="menuitem"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            {props.isProfilePage ? 'Back to Drive' : 'Profile Settings'}
          </button>
          <div class="border-t border-gray-700 mt-1 pt-1">
            <button
              type="button"
              onClick={() => { props.onLogout(); closeDropdown(); }}
              class="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-red-600/20 flex items-center gap-2 transition-colors duration-150"
              role="menuitem"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1z" />
              </svg>
              Log Out
            </button>
          </div>
        </div>
      </Show>
    </div>
  );
}
