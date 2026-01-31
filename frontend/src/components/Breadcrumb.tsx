import { For, Show } from 'solid-js';

export interface BreadcrumbItem {
  id: string | null;
  uid: string | null;
  name: string;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
  onNavigate: (index: number) => void;
}

export default function Breadcrumb(props: BreadcrumbProps) {
  return (
    <nav class="flex items-center gap-2 text-sm">
      <For each={props.items}>
        {(item, index) => (
          <>
            <Show when={index() > 0}>
              <svg
                class="w-4 h-4 text-gray-600 flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 5l7 7-7 7"
                />
              </svg>
            </Show>
            
            <Show
              when={index() < props.items.length - 1}
              fallback={
                <span class="text-white font-medium px-2 py-1 rounded bg-gray-800/50">
                  {item.name}
                </span>
              }
            >
              <button
                onClick={() => props.onNavigate(index())}
                class="text-gray-400 hover:text-primary-400 hover:bg-gray-800 px-2 py-1 rounded transition-colors flex items-center gap-1"
              >
                <Show when={index() === 0}>
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                  </svg>
                </Show>
                {item.name}
              </button>
            </Show>
          </>
        )}
      </For>
    </nav>
  );
}
