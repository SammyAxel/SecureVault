import { For, createEffect, onCleanup } from 'solid-js';
import { toast, toasts, type ToastType } from '../stores/toast';

const iconMap: Record<ToastType, string> = {
  success: '✓',
  error: '✕',
  warning: '⚠',
  info: 'ℹ',
};

const bgColorMap: Record<ToastType, string> = {
  success: 'bg-green-600',
  error: 'bg-red-600',
  warning: 'bg-yellow-600',
  info: 'bg-blue-600',
};

const borderColorMap: Record<ToastType, string> = {
  success: 'border-green-500',
  error: 'border-red-500',
  warning: 'border-yellow-500',
  info: 'border-blue-500',
};

export default function ToastContainer() {
  return (
    <div class="fixed top-4 right-4 z-[100] flex flex-col gap-2 max-w-sm">
      <For each={toasts()}>
        {(t) => (
          <div
            class={`flex items-start gap-3 px-4 py-3 rounded-lg border shadow-lg animate-slide-in ${bgColorMap[t.type]} ${borderColorMap[t.type]} bg-opacity-95`}
            role="alert"
          >
            <span class="text-white text-lg font-bold">{iconMap[t.type]}</span>
            <div class="flex-1">
              <p class="text-white text-sm font-medium">{t.message}</p>
            </div>
            <button
              onClick={() => toast.dismiss(t.id)}
              class="text-white/70 hover:text-white text-lg leading-none"
            >
              ×
            </button>
          </div>
        )}
      </For>
    </div>
  );
}
