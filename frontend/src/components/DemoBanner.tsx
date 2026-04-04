import { createSignal, Show } from 'solid-js';

const SURVEY_URL = import.meta.env.VITE_SURVEY_URL as string | undefined;

export default function DemoBanner(props: { onStartTour?: () => void }) {
  const [dismissed, setDismissed] = createSignal(false);

  return (
    <Show when={!dismissed()}>
      <div class="bg-primary-600/90 text-white text-sm">
        <div class="max-w-7xl mx-auto px-3 sm:px-4 py-2.5 flex items-center justify-between gap-3 flex-wrap">
          <div class="flex items-center gap-2 min-w-0">
            <span class="font-semibold shrink-0">Demo Mode</span>
            <span class="hidden sm:inline text-primary-100">
              &mdash; Shared admin key &middot; 25 MB per session &middot; files are deleted on logout
            </span>
          </div>

          <div class="flex items-center gap-2 shrink-0">
            <a
              href="/demo_admin_keys.json"
              download="demo_admin_keys.json"
              class="px-3 py-1 rounded bg-white/20 hover:bg-white/30 text-xs font-medium"
            >
              Download Keys
            </a>

            <Show when={props.onStartTour}>
              <button
                type="button"
                onClick={() => props.onStartTour?.()}
                class="px-3 py-1 rounded bg-white/20 hover:bg-white/30 text-xs font-medium"
              >
                Tour
              </button>
            </Show>

            <Show when={SURVEY_URL}>
              <a
                href={SURVEY_URL}
                target="_blank"
                rel="noopener noreferrer"
                class="px-3 py-1 rounded bg-yellow-400/90 hover:bg-yellow-400 text-gray-900 text-xs font-semibold"
              >
                Survey
              </a>
            </Show>

            <button
              type="button"
              onClick={() => setDismissed(true)}
              class="p-1 rounded hover:bg-white/20"
              aria-label="Dismiss banner"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
}
