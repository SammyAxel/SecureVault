import { createEffect, createMemo, createSignal, For, Show } from 'solid-js';
import * as api from '../lib/api';
import type { FileItem } from '../lib/api';
import { formatSize } from '../lib/format';
import { awaitMinElapsed, MIN_CONTENT_LOAD_MS } from '../lib/motion';
import { formatAbsolute, formatRelative } from '../lib/time';

export default function Home(props: {
  search: string;
  searchLoading?: boolean;
  onGoToDrive?: () => void;
  onOpenFolder: (folderId: string, folderName: string, folderUid?: string | null) => void;
  onOpenFile: (file: FileItem) => void;
  onDownloadFile: (file: FileItem) => void;
}) {
  const [files, setFiles] = createSignal<FileItem[]>([]);
  const [isLoading, setIsLoading] = createSignal(true);
  const [loadError, setLoadError] = createSignal<string | null>(null);
  const [loadNonce, setLoadNonce] = createSignal(0);

  createEffect(() => {
    loadNonce();
    (async () => {
      const started = Date.now();
      setLoadError(null);
      setIsLoading(true);
      try {
        const res = await api.listFiles();
        setFiles(res.files);
      } catch (e: any) {
        setLoadError(e?.message || 'Something went wrong while loading Home.');
      } finally {
        await awaitMinElapsed(started, MIN_CONTENT_LOAD_MS);
        setIsLoading(false);
      }
    })();
  });

  const visible = createMemo(() => {
    const q = props.search.toLowerCase().trim();
    const list = files();
    if (!q) return list;
    return list.filter((f) => f.filename.toLowerCase().includes(q));
  });

  const suggestedFolders = createMemo(() =>
    visible()
      .filter((f) => f.isFolder)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 6)
  );

  const suggestedFiles = createMemo(() =>
    visible()
      .filter((f) => !f.isFolder)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 8)
  );

  const vaultEmpty = () => !props.search.trim() && files().length === 0;
  const searchNoHits = () =>
    !!props.search.trim() && visible().length === 0 && files().length > 0;

  return (
    <div class="pb-20">
      <div class="flex items-center justify-between mb-4 sm:mb-6">
        <div class="min-w-0">
          <h2 class="text-lg sm:text-xl font-semibold text-white truncate">Home</h2>
          <p class="text-sm text-gray-400 mt-1">Suggested content based on recent activity</p>
        </div>
      </div>

      <Show when={loadError()}>
        <div class="bg-red-900/20 border border-red-800/60 rounded-xl p-4 mb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <p class="text-sm text-red-200">{loadError()}</p>
          <button
            type="button"
            onClick={() => setLoadNonce((n) => n + 1)}
            class="shrink-0 px-4 py-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-white text-sm"
          >
            Retry
          </button>
        </div>
      </Show>

      <Show
        when={!isLoading()}
        fallback={
          <div class="bg-gray-900 rounded-lg border border-gray-800">
            <div class="p-6">
              <div class="h-6 w-40 bg-gray-700 rounded animate-pulse mb-5" />
              <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-3 gap-3 mb-8">
                <For each={[0, 1, 2, 3, 4, 5]}>
                  {() => <div class="h-20 bg-gray-800/60 border border-gray-700 rounded-xl animate-pulse" />}
                </For>
              </div>
              <div class="h-6 w-36 bg-gray-700 rounded animate-pulse mb-4" />
              <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 gap-3">
                <For each={[0, 1, 2, 3]}>
                  {() => <div class="h-20 bg-gray-800/60 border border-gray-700 rounded-xl animate-pulse" />}
                </For>
              </div>
            </div>
          </div>
        }
      >
        <Show when={!loadError()}>
          <Show when={vaultEmpty()}>
            <div class="bg-gray-800/40 border border-gray-700 rounded-xl p-8 text-center mb-8">
              <svg class="w-14 h-14 mx-auto text-gray-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              <h3 class="text-white font-medium mb-1">Your vault is empty</h3>
              <p class="text-gray-400 text-sm mb-4 max-w-md mx-auto">
                Upload files or create a folder in My Drive. They will show up here as suggestions.
              </p>
              <Show when={props.onGoToDrive}>
                <button
                  type="button"
                  onClick={() => props.onGoToDrive?.()}
                  class="px-4 py-2 rounded-lg bg-primary-600 hover:bg-primary-700 text-white text-sm font-medium"
                >
                  Open My Drive
                </button>
              </Show>
            </div>
          </Show>

          <Show when={searchNoHits()}>
            <div class="bg-gray-800/40 border border-gray-700 rounded-xl p-6 text-center mb-6">
              <p class="text-gray-300 text-sm mb-3">No results match your search on Home.</p>
              <button
                type="button"
                onClick={() => props.onGoToDrive?.()}
                class="text-primary-400 hover:text-primary-300 text-sm underline"
              >
                Search in My Drive instead
              </button>
            </div>
          </Show>

        <Show when={!vaultEmpty() && !searchNoHits()}>
        <div class="relative animate-sv-rise">
          <div
            class={`space-y-8 transition-opacity duration-300 ease-out ${props.searchLoading ? 'opacity-40 pointer-events-none' : ''}`}
          >
          <section>
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-sm font-semibold text-gray-300 tracking-wide uppercase">Suggested folders</h3>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-3 gap-3 sv-stagger-children">
              <For each={suggestedFolders()}>
                {(f) => (
                  <button
                    type="button"
                    onClick={() => props.onOpenFolder(f.id, f.filename, f.uid || null)}
                    class="group bg-gray-800/60 hover:bg-gray-800 border border-gray-700 rounded-xl p-4 text-left transition-all duration-200 ease-out hover:border-gray-600"
                  >
                    <div class="flex items-center gap-3">
                      <div class="w-10 h-10 rounded-lg bg-yellow-500/10 flex items-center justify-center">
                        <svg class="w-6 h-6 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                          <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                        </svg>
                      </div>
                      <div class="min-w-0">
                        <div class="text-white font-medium truncate group-hover:text-primary-200">{f.filename}</div>
                        <div class="text-xs text-gray-500">Folder</div>
                      </div>
                    </div>
                  </button>
                )}
              </For>
              <Show when={suggestedFolders().length === 0 && !vaultEmpty()}>
                <div class="col-span-2 sm:col-span-3 flex flex-col sm:flex-row sm:items-center gap-3 text-gray-500 text-sm">
                  <span>No folders yet. Create one in My Drive.</span>
                  <Show when={props.onGoToDrive}>
                    <button
                      type="button"
                      onClick={() => props.onGoToDrive?.()}
                      class="text-primary-400 hover:text-primary-300 text-sm font-medium w-fit"
                    >
                      Open My Drive →
                    </button>
                  </Show>
                </div>
              </Show>
            </div>
          </section>

          <section>
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-sm font-semibold text-gray-300 tracking-wide uppercase">Suggested files</h3>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 gap-3 sv-stagger-children">
              <For each={suggestedFiles()}>
                {(f) => (
                  <div class="bg-gray-800/60 border border-gray-700 rounded-xl p-4 flex items-center justify-between gap-3">
                    <div class="min-w-0">
                      <div class="text-white font-medium truncate">{f.filename}</div>
                      <div
                        class="text-xs text-gray-500 mt-0.5"
                        title={formatAbsolute(f.createdAt)}
                      >
                        {formatSize(f.fileSize, { zero: 'dash' })} • {formatRelative(f.createdAt)}
                      </div>
                    </div>
                    <div class="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        class="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-sm"
                        onClick={() => props.onDownloadFile(f)}
                        title="Download"
                      >
                        Download
                      </button>
                      <button
                        type="button"
                        class="px-3 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm"
                        onClick={() => props.onOpenFile(f)}
                        title="Open"
                      >
                        Open
                      </button>
                    </div>
                  </div>
                )}
              </For>
              <Show when={suggestedFiles().length === 0 && !vaultEmpty()}>
                <div class="flex flex-col sm:flex-row sm:items-center gap-3 text-gray-500 text-sm">
                  <span>No files yet. Upload from My Drive.</span>
                  <Show when={props.onGoToDrive}>
                    <button
                      type="button"
                      onClick={() => props.onGoToDrive?.()}
                      class="text-primary-400 hover:text-primary-300 text-sm font-medium w-fit"
                    >
                      Upload in My Drive →
                    </button>
                  </Show>
                </div>
              </Show>
            </div>
          </section>
          </div>
          <Show when={props.searchLoading}>
            <div class="absolute inset-0 flex items-center justify-center rounded-xl bg-gray-900/50 backdrop-blur-[1px] min-h-[220px] z-10">
              <div class="flex flex-col items-center gap-2">
                <div class="animate-spin rounded-full h-10 w-10 border-2 border-primary-400 border-t-transparent" />
                <p class="text-sm text-gray-300">Searching…</p>
              </div>
            </div>
          </Show>
        </div>
        </Show>
        </Show>
      </Show>
    </div>
  );
}
