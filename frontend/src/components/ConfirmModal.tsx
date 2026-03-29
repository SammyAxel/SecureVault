import { Show, createEffect, onCleanup } from 'solid-js';
import { confirmState, closeConfirm } from '../stores/confirm';

export default function ConfirmModal() {
  const handleConfirm = () => {
    const state = confirmState();
    if (state?.onConfirm) {
      state.onConfirm();
    }
    closeConfirm();
  };

  const handleCancel = () => {
    const state = confirmState();
    if (state?.onCancel) {
      state.onCancel();
    }
    closeConfirm();
  };

  createEffect(() => {
    const state = confirmState();
    if (!state) return;

    const previousFocus = document.activeElement as HTMLElement | null;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        handleCancel();
        return;
      }
      if (e.key !== 'Tab') return;
      const panel = document.querySelector('.sv-modal-panel');
      if (!panel || !(panel instanceof HTMLElement)) return;
      const focusables = Array.from(
        panel.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])'
        )
      ).filter((el) => el.offsetParent !== null || el === document.activeElement);
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else if (document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown);
    requestAnimationFrame(() => {
      const panel = document.querySelector('.sv-modal-panel');
      const btn = panel?.querySelector<HTMLButtonElement>('button');
      btn?.focus();
    });

    onCleanup(() => {
      document.removeEventListener('keydown', onKeyDown);
      previousFocus?.focus?.();
    });
  });

  return (
    <Show when={confirmState()}>
      {(state) => (
        <div
          class="fixed inset-0 bg-black/60 flex items-center justify-center z-[90] p-4 sm:p-0 sv-modal-overlay"
          role="presentation"
          onClick={handleCancel}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-modal-title"
            class="bg-vault-panel rounded-xl p-4 sm:p-6 max-w-md w-full mx-0 sm:mx-4 border border-vault-border shadow-vault-float max-h-[90vh] overflow-y-auto sv-modal-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="flex items-center gap-3 mb-4">
              <div
                class={`w-10 h-10 rounded-full flex items-center justify-center ${
                  state().type === 'danger'
                    ? 'bg-red-600/20'
                    : state().type === 'info'
                      ? 'bg-blue-600/20'
                      : 'bg-yellow-600/20'
                }`}
                aria-hidden="true"
              >
                <svg
                  class={`w-5 h-5 ${
                    state().type === 'danger'
                      ? 'text-red-400'
                      : state().type === 'info'
                        ? 'text-blue-400'
                        : 'text-yellow-400'
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
              </div>
              <h3 id="confirm-modal-title" class="text-lg font-semibold text-white">
                {state().title || 'Confirm Action'}
              </h3>
            </div>

            <p class="text-gray-300 mb-6">{state().message}</p>

            <div class="flex justify-end gap-3">
              <button
                type="button"
                onClick={handleCancel}
                class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
              >
                {state().cancelText || 'Cancel'}
              </button>
              <button
                type="button"
                onClick={handleConfirm}
                class={`px-4 py-2 rounded-lg transition-colors ${
                  state().confirmButtonClass
                    ? `${state().confirmButtonClass} text-white`
                    : state().type === 'danger'
                      ? 'bg-red-600 hover:bg-red-700 text-white'
                      : state().type === 'info'
                        ? 'bg-blue-600 hover:bg-blue-700 text-white'
                        : 'bg-primary-600 hover:bg-primary-700 text-white'
                }`}
              >
                {state().confirmText || 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </Show>
  );
}
