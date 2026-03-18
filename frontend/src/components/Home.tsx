import { createEffect, createSignal, For, Show } from 'solid-js';
import * as api from '../lib/api';
import type { FileItem } from '../lib/api';
import { toast } from '../stores/toast';

export default function Home(props: {
  search: string;
  onOpenFolder: (folderId: string, folderName: string, folderUid?: string | null) => void;
  onOpenFile: (file: FileItem) => void;
  onDownloadFile: (file: FileItem) => void;
}) {
  const [files, setFiles] = createSignal<FileItem[]>([]);
  const [isLoading, setIsLoading] = createSignal(true);

  createEffect(() => {
    (async () => {
      setIsLoading(true);
      try {
        const res = await api.listFiles();
        setFiles(res.files);
      } catch (e: any) {
        toast.error(e?.message || 'Failed to load Home');
      } finally {
        setIsLoading(false);
      }
    })();
  });

  const query = () => props.search.toLowerCase().trim();
  const visible = () => {
    const q = query();
    if (!q) return files();
    return files().filter((f) => f.filename.toLowerCase().includes(q));
  };

  const suggestedFolders = () =>
    visible()
      .filter((f) => f.isFolder)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 6);

  const suggestedFiles = () =>
    visible()
      .filter((f) => !f.isFolder)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 8);

  const formatSize = (bytes: number) => {
    if (!bytes) return '—';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  return (
    <div class="pb-20">
      <div class="flex items-center justify-between mb-4 sm:mb-6">
        <div class="min-w-0">
          <h2 class="text-lg sm:text-xl font-semibold text-white truncate">Home</h2>
          <p class="text-sm text-gray-400 mt-1">Suggested content based on recent activity</p>
        </div>
      </div>

      <Show when={!isLoading()} fallback={
        <div class="bg-gray-800/60 border border-gray-700 rounded-xl p-6">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500 mx-auto mb-3"></div>
          <p class="text-gray-400 text-center text-sm">Loading…</p>
        </div>
      }>
        <div class="space-y-8">
          <section>
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-sm font-semibold text-gray-300 tracking-wide uppercase">Suggested folders</h3>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-3 gap-3">
              <For each={suggestedFolders()}>
                {(f) => (
                  <button
                    type="button"
                    onClick={() => props.onOpenFolder(f.id, f.filename, f.uid || null)}
                    class="group bg-gray-800/60 hover:bg-gray-800 border border-gray-700 rounded-xl p-4 text-left transition-colors"
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
              <Show when={suggestedFolders().length === 0}>
                <div class="col-span-2 sm:col-span-3 text-gray-500 text-sm">
                  No folders yet. Create one in My Drive to get started.
                </div>
              </Show>
            </div>
          </section>

          <section>
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-sm font-semibold text-gray-300 tracking-wide uppercase">Suggested files</h3>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 gap-3">
              <For each={suggestedFiles()}>
                {(f) => (
                  <div class="bg-gray-800/60 border border-gray-700 rounded-xl p-4 flex items-center justify-between gap-3">
                    <div class="min-w-0">
                      <div class="text-white font-medium truncate">{f.filename}</div>
                      <div class="text-xs text-gray-500 mt-0.5">{formatSize(f.fileSize)} • {new Date(f.createdAt).toLocaleDateString()}</div>
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
              <Show when={suggestedFiles().length === 0}>
                <div class="text-gray-500 text-sm">No files yet. Upload something in My Drive.</div>
              </Show>
            </div>
          </section>
        </div>
      </Show>
    </div>
  );
}

