import { createSignal, createEffect, For, Show, createMemo } from 'solid-js';
import * as api from '../../lib/api';
import type { PublicShareItem } from '../../lib/api';
import { formatSize } from '../../lib/format';
import { formatRelative } from '../../lib/time';
import { toast } from '../../stores/toast';
import { openConfirm } from '../../stores/confirm';
import { logger } from '../../lib/logger';
import {
  getCurrentKeys,
  importEncryptionPrivateKey,
  unwrapKey,
  decryptFilename,
  isEncryptedFilename,
} from '../../lib/crypto';

export default function ShareManagement() {
  const [publicShares, setPublicShares] = createSignal<PublicShareItem[]>([]);
  const [isLoading, setIsLoading] = createSignal(true);

  // Stats
  const stats = createMemo(() => {
    const ps = publicShares();
    const activeLinks = ps.filter((p) => !p.isExpired);
    const expiredLinks = ps.filter((p) => p.isExpired);
    const totalAccesses = ps.reduce((sum, p) => sum + p.accessCount, 0);
    return {
      activeLinks: activeLinks.length,
      expiredLinks: expiredLinks.length,
      totalAccesses,
    };
  });

  /**
   * Decrypt encrypted filenames in share items.
   * Uses the owner's private key since these are files the user owns.
   */
  const decryptShareFilenames = async <T extends { filename: string; fileId: string }>(
    items: T[]
  ): Promise<T[]> => {
    const keys = getCurrentKeys();
    if (!keys) return items;

    const hasEncrypted = items.some((f) => isEncryptedFilename(f.filename));
    if (!hasEncrypted) return items;

    let privateKey: CryptoKey;
    try {
      privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
    } catch {
      return items;
    }

    // We need the encryptedKey for each file to decrypt names.
    // Fetch all files once to build a lookup.
    let fileLookup: Record<string, string> = {};
    try {
      const allFiles = await api.listFiles(undefined, undefined, true);
      for (const f of allFiles.files) {
        fileLookup[f.id] = f.encryptedKey;
      }
    } catch {
      return items;
    }

    return Promise.all(
      items.map(async (item) => {
        if (!isEncryptedFilename(item.filename)) return item;
        const encKey = fileLookup[item.fileId];
        if (!encKey) return item;
        try {
          const fileKey = await unwrapKey(encKey, privateKey);
          const name = await decryptFilename(item.filename, fileKey);
          return { ...item, filename: name };
        } catch {
          return item;
        }
      })
    );
  };

  const loadShares = async () => {
    setIsLoading(true);
    try {
      const result = await api.getMyShares();
      const decryptedPublicShares = await decryptShareFilenames(result.publicShares);
      setPublicShares(decryptedPublicShares);
    } catch (err) {
      logger.error('Failed to load shares:', err);
      toast.error('Failed to load share data');
    } finally {
      setIsLoading(false);
    }
  };

  createEffect(() => {
    loadShares();
  });

  const handleDeletePublicLink = async (share: PublicShareItem) => {
    const confirmed = await openConfirm({
      title: 'Delete Public Link',
      message: `Delete the public share link for "${share.filename}"? Anyone with this link will lose access immediately.`,
      confirmText: 'Delete Link',
      type: 'danger',
    });
    if (!confirmed) return;

    try {
      await api.deletePublicShare(share.token);
      toast.success(`Deleted public link for "${share.filename}"`);
      loadShares();
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete link');
    }
  };

  const copyPublicLink = async (token: string) => {
    const url = `${window.location.origin}/share/${token}`;
    try {
      await navigator.clipboard.writeText(url);
      toast.success('Link copied to clipboard');
    } catch {
      toast.error('Failed to copy link');
    }
  };

  // File icon helper
  const FileIcon = (props: { isFolder: boolean }) => (
    <Show
      when={props.isFolder}
      fallback={
        <svg class="w-5 h-5 text-gray-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
          <path
            fill-rule="evenodd"
            d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z"
            clip-rule="evenodd"
          />
        </svg>
      }
    >
      <svg class="w-5 h-5 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
        <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
      </svg>
    </Show>
  );

  return (
    <div class="animate-sv-rise">
      {/* Header */}
      <div class="flex items-center justify-between mb-6">
        <div>
          <h2 class="text-xl font-bold text-white">Share Management</h2>
          <p class="text-sm text-gray-400 mt-1">Monitor and manage all your shared files and links</p>
        </div>
        <button
          type="button"
          onClick={() => loadShares()}
          class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
          title="Refresh"
          aria-label="Refresh shares"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
            />
          </svg>
        </button>
      </div>

      {/* Stats Cards */}
      <div class="grid grid-cols-2 gap-3 mb-6">
        <div class="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4">
          <div class="text-2xl font-bold text-emerald-400">{stats().activeLinks}</div>
          <div class="text-xs text-gray-400 mt-1">Active Links</div>
        </div>
        <div class="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4">
          <div class="text-2xl font-bold text-white">{stats().totalAccesses}</div>
          <div class="text-xs text-gray-400 mt-1">Total Views</div>
        </div>
      </div>

      {/* Loading State */}
      <Show when={isLoading()}>
        <div class="flex items-center justify-center py-16">
          <div class="flex flex-col items-center gap-3">
            <div class="animate-spin rounded-full h-10 w-10 border-2 border-primary-500/30 border-t-primary-500" />
            <span class="text-sm text-gray-400">Loading shares…</span>
          </div>
        </div>
      </Show>

      {/* Public Links Tab */}
      <Show when={!isLoading()}>
        <Show
          when={publicShares().length > 0}
          fallback={
            <div class="text-center py-16">
              <svg
                class="w-16 h-16 text-gray-600 mx-auto mb-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="1.5"
                  d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
                />
              </svg>
              <h3 class="text-lg font-medium text-gray-300 mb-1">No public links</h3>
              <p class="text-sm text-gray-500">
                When you create public share links, they'll be tracked here
              </p>
            </div>
          }
        >
          <div class="space-y-2">
            <For each={publicShares()}>
              {(share) => {
                const isExpired = () => share.isExpired;
                const accessText = () => {
                  if (share.maxAccess) {
                    return `${share.accessCount} / ${share.maxAccess} views`;
                  }
                  return `${share.accessCount} views`;
                };

                return (
                  <div
                    class={`flex items-center gap-3 p-4 border rounded-xl transition-colors group ${
                      isExpired()
                        ? 'bg-gray-800/20 border-gray-700/30 opacity-60'
                        : 'bg-gray-800/40 border-gray-700/50 hover:bg-gray-800/60'
                    }`}
                  >
                    <FileIcon isFolder={share.isFolder} />
                    <div class="flex-1 min-w-0">
                      <div class="flex items-center gap-2">
                        <span class="text-sm font-medium text-white truncate">{share.filename}</span>
                        <span
                          class={`px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded-full ${
                            isExpired()
                              ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                              : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          }`}
                        >
                          {isExpired() ? 'Inactive' : 'Active'}
                        </span>
                      </div>
                      <div class="flex items-center gap-2 mt-1 text-xs text-gray-400 flex-wrap">
                        <span class="flex items-center gap-1">
                          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path
                              stroke-linecap="round"
                              stroke-linejoin="round"
                              stroke-width="2"
                              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                            />
                            <path
                              stroke-linecap="round"
                              stroke-linejoin="round"
                              stroke-width="2"
                              d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                            />
                          </svg>
                          {accessText()}
                        </span>
                        <span>·</span>
                        <span>{formatSize(share.fileSize)}</span>
                        <span>·</span>
                        <span>
                          Expires {share.expiresAt ? formatRelative(share.expiresAt) : '—'}
                        </span>
                      </div>
                    </div>
                    <div class="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                      <Show when={!isExpired()}>
                        <button
                          type="button"
                          onClick={() => copyPublicLink(share.token)}
                          class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
                          title="Copy link"
                          aria-label="Copy public link"
                        >
                          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path
                              stroke-linecap="round"
                              stroke-linejoin="round"
                              stroke-width="2"
                              d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"
                            />
                          </svg>
                        </button>
                      </Show>
                      <button
                        type="button"
                        onClick={() => handleDeletePublicLink(share)}
                        class="p-2 rounded-lg text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
                        title="Delete link"
                        aria-label="Delete public link"
                      >
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                          />
                        </svg>
                      </button>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </Show>
    </div>
  );
}
