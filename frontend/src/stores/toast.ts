import { createSignal } from 'solid-js';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface ToastItem {
  id: string;
  type: ToastType;
  message: string;
  duration: number;
}

const [toasts, setToasts] = createSignal<ToastItem[]>([]);

let toastId = 0;

const addToast = (type: ToastType, message: string, duration = 4000) => {
  const id = `toast-${++toastId}`;
  
  setToasts((prev) => [...prev, { id, type, message, duration }]);
  
  if (duration > 0) {
    setTimeout(() => {
      dismiss(id);
    }, duration);
  }
  
  return id;
};

const dismiss = (id: string) => {
  setToasts((prev) => prev.filter((t) => t.id !== id));
};

const dismissAll = () => {
  setToasts([]);
};

export const toast = {
  success: (message: string, duration?: number) => addToast('success', message, duration),
  error: (message: string, duration?: number) => addToast('error', message, duration ?? 5000),
  warning: (message: string, duration?: number) => addToast('warning', message, duration),
  info: (message: string, duration?: number) => addToast('info', message, duration),
  dismiss,
  dismissAll,
};

export { toasts };
