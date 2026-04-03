import { Show } from 'solid-js';
import { saveBlobToDevice } from '../lib/downloadBlob';
import { toast } from '../stores/toast';

/** Shown after decrypt on mobile: user must tap once so the save runs under a fresh user gesture. */
export default function BlobSavePrompt(props: {
  pending: { blob: Blob; filename: string } | null;
  onClose: () => void;
}) {
  return (
    <Show when={props.pending}>
      {(p) => (
        <div
          class="fixed inset-0 z-[80] flex items-end sm:items-center justify-center p-4 bg-black/70"
          role="dialog"
          aria-modal="true"
          aria-labelledby="blob-save-title"
        >
          <div class="w-full max-w-md rounded-xl border border-gray-700 bg-gray-800 p-4 shadow-vault-float">
            <h3 id="blob-save-title" class="text-lg font-medium text-white mb-1">
              File ready
            </h3>
            <p class="text-sm text-gray-400 mb-4">
              On phones, tap <span class="text-gray-200">Save to device</span> so your browser can store the file
              (downloads after decrypt need a direct tap).
            </p>
            <p class="text-xs text-gray-500 truncate mb-4" title={p().filename}>
              {p().filename}
            </p>
            <div class="flex gap-2 justify-end">
              <button
                type="button"
                class="px-4 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-700"
                onClick={() => props.onClose()}
              >
                Cancel
              </button>
              <button
                type="button"
                class="px-4 py-2 rounded-lg text-sm bg-primary-600 hover:bg-primary-700 text-white font-medium"
                onClick={async () => {
                  const { blob, filename } = p();
                  try {
                    await saveBlobToDevice(blob, filename);
                    props.onClose();
                  } catch (err: unknown) {
                    const message = err instanceof Error ? err.message : String(err);
                    toast.error(message ? `Save failed: ${message}` : 'Could not save the file. Try again.');
                  }
                }}
              >
                Save to device
              </button>
            </div>
          </div>
        </div>
      )}
    </Show>
  );
}
