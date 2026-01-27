import { Show } from 'solid-js';
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

  return (
    <Show when={confirmState()}>
      {(state) => (
        <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-[90]">
          <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 border border-gray-700 shadow-xl">
            {/* Header */}
            <div class="flex items-center gap-3 mb-4">
              <div class={`w-10 h-10 rounded-full flex items-center justify-center ${
                state().type === 'danger' ? 'bg-red-600/20' : 'bg-yellow-600/20'
              }`}>
                <svg 
                  class={`w-5 h-5 ${state().type === 'danger' ? 'text-red-400' : 'text-yellow-400'}`}
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
              <h3 class="text-lg font-semibold text-white">
                {state().title || 'Confirm Action'}
              </h3>
            </div>

            {/* Message */}
            <p class="text-gray-300 mb-6">
              {state().message}
            </p>

            {/* Buttons */}
            <div class="flex justify-end gap-3">
              <button
                onClick={handleCancel}
                class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
              >
                {state().cancelText || 'Cancel'}
              </button>
              <button
                onClick={handleConfirm}
                class={`px-4 py-2 rounded-lg transition-colors ${
                  state().type === 'danger'
                    ? 'bg-red-600 hover:bg-red-700 text-white'
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
