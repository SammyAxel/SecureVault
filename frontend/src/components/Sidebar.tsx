import { Show } from 'solid-js';
import { useAuth } from '../stores/auth';

export type DriveSection = 'home' | 'drive' | 'shared' | 'trash';

export default function Sidebar(props: {
  active: DriveSection;
  onNavigate: (section: DriveSection) => void;
}) {
  const { user } = useAuth();

  const formatSize = (bytes: number) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1)} ${sizes[i]}`;
  };

  const storagePercent = () => {
    const u = user();
    if (!u) return 0;
    return Math.min(100, Math.round((u.storageUsed / Math.max(1, u.storageQuota)) * 100));
  };

  const NavItem = (p: {
    id: DriveSection;
    label: string;
    icon: any;
  }) => (
    <button
      type="button"
      onClick={() => props.onNavigate(p.id)}
      class={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
        props.active === p.id
          ? 'bg-primary-600/20 text-primary-200 ring-1 ring-primary-500/40'
          : 'text-gray-300 hover:bg-gray-800 hover:text-white'
      }`}
    >
      <span class="w-5 h-5 flex items-center justify-center text-gray-400">{p.icon}</span>
      <span class="truncate">{p.label}</span>
    </button>
  );

  return (
    <aside class="hidden lg:flex lg:flex-col w-64 shrink-0">
      <div class="sticky top-0 pt-6">
        <div class="bg-gray-900/40 border border-gray-800 rounded-xl p-3">
          <div class="text-xs font-semibold text-gray-400 uppercase tracking-wider px-1 mb-2">
            Drive
          </div>
          <div class="space-y-1">
            <NavItem
              id="home"
              label="Home"
              icon={
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                </svg>
              }
            />
            <NavItem
              id="drive"
              label="My Drive"
              icon={
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
              }
            />
            <NavItem
              id="shared"
              label="Shared with me"
              icon={
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
            />
            <NavItem
              id="trash"
              label="Trash"
              icon={
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              }
            />
          </div>
        </div>

        <Show when={user()}>
          <div class="mt-4 bg-gray-900/40 border border-gray-800 rounded-xl p-4">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Storage</span>
              <span class="text-xs text-gray-400">{storagePercent()}%</span>
            </div>
            <div class="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
              <div
                class="bg-primary-500 h-2 rounded-full transition-all"
                style={{ width: `${storagePercent()}%` }}
              />
            </div>
            <div class="mt-2 text-xs text-gray-400">
              {formatSize(user()!.storageUsed)} / {formatSize(user()!.storageQuota)}
            </div>
          </div>
        </Show>
      </div>
    </aside>
  );
}

