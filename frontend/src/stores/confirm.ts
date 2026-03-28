import { createSignal } from 'solid-js';

export interface ConfirmOptions {
  title?: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  /** Visual severity; drives default icon and confirm button styling unless `confirmButtonClass` is set. */
  type?: 'danger' | 'warning' | 'info';
  /** Optional Tailwind classes for the confirm button (overrides default type-based styles). */
  confirmButtonClass?: string;
  onConfirm?: () => void;
  onCancel?: () => void;
}

const [confirmState, setConfirmState] = createSignal<ConfirmOptions | null>(null);

export const openConfirm = (options: ConfirmOptions): Promise<boolean> => {
  return new Promise((resolve) => {
    setConfirmState({
      ...options,
      onConfirm: () => {
        options.onConfirm?.();
        resolve(true);
      },
      onCancel: () => {
        options.onCancel?.();
        resolve(false);
      },
    });
  });
};

export const closeConfirm = () => {
  setConfirmState(null);
};

export { confirmState };
