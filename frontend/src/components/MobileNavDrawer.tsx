import { Show, createEffect, onCleanup } from 'solid-js';
import DriveNavPanel from './DriveNavPanel';
import type { DriveSection } from '../lib/routes';

export default function MobileNavDrawer(props: {
  open: boolean;
  onClose: () => void;
  active: DriveSection;
  onNavigate: (section: DriveSection) => void;
}) {
  createEffect(() => {
    if (!props.open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    onCleanup(() => {
      document.body.style.overflow = prev;
    });
  });

  createEffect(() => {
    if (!props.open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') props.onClose();
    };
    document.addEventListener('keydown', onKey);
    onCleanup(() => document.removeEventListener('keydown', onKey));
  });

  return (
    <Show when={props.open}>
      <div class="fixed inset-0 z-[60] lg:hidden" role="dialog" aria-modal="true" aria-label="Drive navigation">
        <button
          type="button"
          class="absolute inset-0 bg-black/60 border-0 cursor-default"
          onClick={() => props.onClose()}
          aria-label="Close navigation"
        />
        <div class="absolute left-0 top-0 bottom-0 w-[min(288px,88vw)] bg-gray-900 border-r border-gray-800 shadow-vault-float flex flex-col pt-[max(0px,env(safe-area-inset-top))]">
          <div class="flex items-center justify-between px-3 py-3 border-b border-gray-800 shrink-0">
            <span class="text-sm font-semibold text-white">Menu</span>
            <button
              type="button"
              onClick={() => props.onClose()}
              class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800"
              aria-label="Close menu"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div class="p-3 overflow-y-auto flex-1">
            <DriveNavPanel
              active={props.active}
              onNavigate={props.onNavigate}
              afterNavigate={() => props.onClose()}
            />
          </div>
        </div>
      </div>
    </Show>
  );
}
