import { For, createEffect, onCleanup, createSignal } from 'solid-js';
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

function ToastItem(props: { toast: typeof toasts extends () => infer T ? T extends Array<infer U> ? U : never : never }) {
  const [progress, setProgress] = createSignal(100);
  
  createEffect(() => {
    if (props.toast.duration > 0) {
      const startTime = Date.now();
      const interval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const remaining = Math.max(0, 100 - (elapsed / props.toast.duration) * 100);
        setProgress(remaining);
        
        if (remaining === 0) {
          clearInterval(interval);
        }
      }, 16); // ~60fps
      
      onCleanup(() => clearInterval(interval));
    }
  });
  
  return (
    <div
      class={`relative overflow-hidden flex items-start gap-3 px-4 py-3 rounded-lg border shadow-lg animate-slide-in ${bgColorMap[props.toast.type]} ${borderColorMap[props.toast.type]} bg-opacity-95`}
      role="alert"
    >
      {/* Progress bar */}
      {props.toast.duration > 0 && (
        <div 
          class="absolute bottom-0 left-0 h-1 bg-white/30 transition-all duration-[16ms] linear"
          style={{ width: `${progress()}%` }}
        />
      )}
      
      <span class="text-white text-lg font-bold">{iconMap[props.toast.type]}</span>
      <div class="flex-1">
        <p class="text-white text-sm font-medium">{props.toast.message}</p>
      </div>
      <button
        onClick={() => toast.dismiss(props.toast.id)}
        class="text-white/70 hover:text-white text-lg leading-none"
      >
        ×
      </button>
    </div>
  );
}

export default function ToastContainer() {
  return (
    <div class="fixed top-4 right-4 z-[100] flex flex-col gap-2 max-w-sm">
      <For each={toasts()}>
        {(t) => <ToastItem toast={t} />}
      </For>
    </div>
  );
}
