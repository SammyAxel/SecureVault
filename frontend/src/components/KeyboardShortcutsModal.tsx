import { Show, type JSX } from 'solid-js';

interface KeyboardShortcutsModalProps {
  open: boolean;
  onClose: () => void;
}

function Kbd(props: { children: JSX.Element }) {
  return (
    <kbd class="inline-flex items-center justify-center min-w-[1.75rem] px-2 py-0.5 rounded-md bg-gray-700 border border-gray-600 text-gray-200 text-xs font-mono font-medium shadow-sm">
      {props.children}
    </kbd>
  );
}

function Row(props: { keys: JSX.Element; label: string }) {
  return (
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 sm:gap-4 py-3 border-b border-gray-700/80 last:border-0">
      <span class="text-sm text-gray-300">{props.label}</span>
      <div class="flex flex-wrap items-center gap-1.5 shrink-0">{props.keys}</div>
    </div>
  );
}

export default function KeyboardShortcutsModal(props: KeyboardShortcutsModalProps) {
  const isMac =
    typeof navigator !== 'undefined' &&
    (navigator.platform.includes('Mac') || navigator.userAgent.includes('Mac'));

  return (
    <Show when={props.open}>
      <div
        class="fixed inset-0 bg-black/80 z-[80] flex items-center justify-center p-4 sv-modal-overlay"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sv-shortcuts-title"
        onClick={props.onClose}
      >
        <div
          class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden shadow-vault-float sv-modal-panel border border-gray-700"
          onClick={(e) => e.stopPropagation()}
        >
          <div class="flex items-center justify-between px-5 py-4 border-b border-gray-700">
            <h2 id="sv-shortcuts-title" class="text-lg font-semibold text-white">
              Keyboard shortcuts
            </h2>
            <button
              type="button"
              onClick={props.onClose}
              class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              aria-label="Close"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div class="px-5 py-2 max-h-[min(70vh,420px)] overflow-y-auto">
            <Row
              label="Focus vault search"
              keys={
                <>
                  <Kbd>/</Kbd>
                  <span class="text-gray-500 text-xs px-0.5">or</span>
                  <Kbd>{isMac ? '⌘' : 'Ctrl'}</Kbd>
                  <Kbd>K</Kbd>
                </>
              }
            />
            <Row
              label="Open this help"
              keys={
                <>
                  <Kbd>?</Kbd>
                  <span class="text-gray-500 text-xs hidden sm:inline pl-1">Shift + /</span>
                </>
              }
            />
            <Row label="Close search sheet (mobile)" keys={<Kbd>Esc</Kbd>} />
            <Row
              label="Go to Home"
              keys={<span class="text-sm text-gray-400">Click the SecureVault logo</span>}
            />

            <div class="pt-3 mt-1 border-t border-gray-700">
              <p class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{'My Drive & Trash'}</p>
              <Row
                label="Up one folder"
                keys={
                  isMac ? (
                    <>
                      <Kbd>⌘</Kbd>
                      <Kbd>↑</Kbd>
                      <span class="text-gray-500 text-xs pl-1 hidden sm:inline">Finder-style</span>
                    </>
                  ) : (
                    <>
                      <Kbd>Alt</Kbd>
                      <Kbd>↑</Kbd>
                      <span class="text-gray-500 text-xs pl-1 hidden sm:inline">Explorer-style</span>
                    </>
                  )
                }
              />
              <Row
                label="Jump to a parent folder"
                keys={
                  <span class="text-sm text-gray-400 text-right sm:text-left">
                    Click its name in the path bar above the list
                  </span>
                }
              />
            </div>

            <div class="pt-3 mt-1 border-t border-gray-700">
              <p class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">File list</p>
              <p class="text-xs text-gray-500 mb-2">Tab to the file table (focus outline), then:</p>
              <Row
                label="Move between rows"
                keys={
                  <>
                    <Kbd>↑</Kbd>
                    <Kbd>↓</Kbd>
                  </>
                }
              />
              <Row
                label="Jump to first / last row"
                keys={
                  <>
                    <Kbd>Home</Kbd>
                    <Kbd>End</Kbd>
                  </>
                }
              />
              <Row label="Open folder or preview file" keys={<Kbd>Enter</Kbd>} />
              <Row label="Clear row highlight" keys={<Kbd>Esc</Kbd>} />
            </div>
          </div>
          <div class="px-5 py-3 bg-gray-900/30 border-t border-gray-700">
            <p class="text-xs text-gray-500">
              Shortcuts are disabled while typing in a field. Press Esc to close this dialog. Folder shortcuts work on
              My Drive and Trash (not on Home). Row keys work when the file list has focus.
            </p>
          </div>
        </div>
      </div>
    </Show>
  );
}
