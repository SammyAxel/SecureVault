import { createSignal, createEffect, For, Show, createMemo, onCleanup } from 'solid-js';
import { Portal } from 'solid-js/web';
import * as api from '../../lib/api';
import type { PublicShareItem, UserShareItem, SharedWithMeItem } from '../../lib/api';
import { formatSize } from '../../lib/format';
import { formatRelative } from '../../lib/time';
import { toast } from '../../stores/toast';
import { openConfirm } from '../../stores/confirm';
import { logger } from '../../lib/logger';
import { saveBlobToDevice } from '../../lib/downloadBlob';
import { getPreviewMimeType, isPreviewableFile, CsvPreview, ExcelPreview, WordPreview } from '../FilePreview';
import DashboardTextPreview from './DashboardTextPreview';
import {
  getCurrentKeys,
  importEncryptionPrivateKey,
  unwrapKey,
  decryptFile,
  decryptFilename,
  isEncryptedFilename,
  base64ToUint8Array,
} from '../../lib/crypto';

type ShareTab = 'received' | 'sent';

const FolderIcon = () => (
  <svg class="w-5 h-5 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
    <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
  </svg>
);

const DocIcon = () => (
  <svg class="w-5 h-5 text-gray-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
    <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
  </svg>
);

const SpinnerIcon = () => (
  <div class="w-4 h-4 rounded-full border-2 border-primary-400/30 border-t-primary-400 animate-spin" />
);

const ItemIcon = (props: { isFolder: boolean }) => (
  <Show when={props.isFolder} fallback={<DocIcon />}>
    <FolderIcon />
  </Show>
);

export default function ShareManagement() {
  const [tab, setTab] = createSignal<ShareTab>('received');
  const [isLoading, setIsLoading] = createSignal(true);

  const [sharedWithMe, setSharedWithMe] = createSignal<SharedWithMeItem[]>([]);
  const [userShares, setUserShares] = createSignal<UserShareItem[]>([]);
  const [publicShares, setPublicShares] = createSignal<PublicShareItem[]>([]);
  const [busyFileId, setBusyFileId] = createSignal<string | null>(null);

  // Folder navigation for "Shared with me"
  const [folderStack, setFolderStack] = createSignal<Array<{ id: string; name: string }>>([]);

  // Preview modal
  const [previewState, setPreviewState] = createSignal<{
    url: string; filename: string; mimeType: string;
  } | null>(null);

  onCleanup(() => {
    const p = previewState();
    if (p) URL.revokeObjectURL(p.url);
  });

  const stats = createMemo(() => ({
    receivedCount: sharedWithMe().length,
    userShareCount: userShares().length,
    activeLinks: publicShares().filter((p) => !p.isExpired).length,
    totalViews: publicShares().reduce((s, p) => s + p.accessCount, 0),
  }));

  // Current folder in the "Shared with me" browser
  const currentFolderId = createMemo<string | null>(() => {
    const stack = folderStack();
    return stack.length > 0 ? stack[stack.length - 1].id : null;
  });

  // Items visible at the current folder level
  const visibleItems = createMemo(() => {
    const all = sharedWithMe();
    const sharedIds = new Set(all.map((i) => i.fileId));
    const cfId = currentFolderId();

    if (cfId === null) {
      // Top level: items whose parentId is null or whose parent is NOT in the shared set
      return all.filter((i) => !i.parentId || !sharedIds.has(i.parentId));
    }
    return all.filter((i) => i.parentId === cfId);
  });

  // Decrypt filenames for items I own
  const decryptOwnerFilenames = async <T extends { filename: string; fileId: string }>(
    items: T[],
    fileLookup: Record<string, string>,
    privateKey: CryptoKey
  ): Promise<T[]> =>
    Promise.all(
      items.map(async (item) => {
        if (!isEncryptedFilename(item.filename)) return item;
        const encKey = fileLookup[item.fileId];
        if (!encKey) return item;
        try {
          const fileKey = await unwrapKey(encKey, privateKey);
          return { ...item, filename: await decryptFilename(item.filename, fileKey) };
        } catch {
          return item;
        }
      })
    );

  // Decrypt filenames for files shared with me using each item's own encryptedKey
  const decryptReceivedFilenames = async (
    items: SharedWithMeItem[],
    privateKey: CryptoKey
  ): Promise<SharedWithMeItem[]> =>
    Promise.all(
      items.map(async (item) => {
        if (!isEncryptedFilename(item.filename)) return item;
        try {
          const fileKey = await unwrapKey(item.encryptedKey, privateKey);
          return { ...item, filename: await decryptFilename(item.filename, fileKey) };
        } catch {
          return item;
        }
      })
    );

  const loadAll = async () => {
    setIsLoading(true);
    try {
      const [mySharesResult, receivedResult] = await Promise.all([
        api.getMyShares(),
        api.getSharedWithMe(),
      ]);

      const keys = getCurrentKeys();
      if (!keys) {
        setPublicShares(mySharesResult.publicShares ?? []);
        setUserShares(mySharesResult.userShares ?? []);
        setSharedWithMe(receivedResult.items ?? []);
        return;
      }

      let privateKey: CryptoKey | null = null;
      try {
        privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      } catch { /* use raw filenames */ }

      if (!privateKey) {
        setPublicShares(mySharesResult.publicShares ?? []);
        setUserShares(mySharesResult.userShares ?? []);
        setSharedWithMe(receivedResult.items ?? []);
        return;
      }

      const pk = privateKey;
      let fileLookup: Record<string, string> = {};
      const allOwned = [...(mySharesResult.publicShares ?? []), ...(mySharesResult.userShares ?? [])];
      if (allOwned.some((f) => isEncryptedFilename(f.filename))) {
        try {
          const all = await api.listFiles(undefined, undefined, true);
          for (const f of all.files) fileLookup[f.id] = f.encryptedKey;
        } catch { /* ignore */ }
      }

      const [decPub, decUser, decReceived] = await Promise.all([
        decryptOwnerFilenames(mySharesResult.publicShares ?? [], fileLookup, pk),
        decryptOwnerFilenames(mySharesResult.userShares ?? [], fileLookup, pk),
        decryptReceivedFilenames(receivedResult.items ?? [], pk),
      ]);

      setPublicShares(decPub);
      setUserShares(decUser);
      setSharedWithMe(decReceived);
    } catch (err) {
      logger.error('Failed to load shares:', err);
      toast.error('Failed to load sharing data');
    } finally {
      setIsLoading(false);
    }
  };

  createEffect(() => {
    loadAll();
  });

  const decryptAndGetBlob = async (item: SharedWithMeItem): Promise<Blob> => {
    const keys = getCurrentKeys();
    if (!keys) throw new Error('Please login again — keys not found');
    const { data, encryptedKey, iv } = await api.downloadFile(item.fileId);
    const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
    const fileKey = await unwrapKey(encryptedKey, privateKey);
    const decrypted = await decryptFile(data, fileKey, base64ToUint8Array(iv));
    return new Blob([decrypted], { type: getPreviewMimeType(item.filename) });
  };

  const handleDownload = async (item: SharedWithMeItem) => {
    setBusyFileId(item.fileId);
    try {
      const blob = await decryptAndGetBlob(item);
      await saveBlobToDevice(blob, item.filename);
    } catch (err: any) {
      logger.error('Download failed:', err);
      toast.error(`Download failed: ${err.message}`);
    } finally {
      setBusyFileId(null);
    }
  };

  const handlePreview = async (item: SharedWithMeItem) => {
    setBusyFileId(item.fileId);
    try {
      const blob = await decryptAndGetBlob(item);
      const url = URL.createObjectURL(blob);
      const prev = previewState();
      if (prev) URL.revokeObjectURL(prev.url);
      setPreviewState({ url, filename: item.filename, mimeType: blob.type });
    } catch (err: any) {
      logger.error('Preview failed:', err);
      toast.error(`Preview failed: ${err.message}`);
    } finally {
      setBusyFileId(null);
    }
  };

  const handleEnterFolder = (item: SharedWithMeItem) => {
    setFolderStack((s) => [...s, { id: item.fileId, name: item.filename }]);
  };

  const navigateToBreadcrumb = (index: number) => {
    if (index < 0) {
      setFolderStack([]);
    } else {
      setFolderStack((s) => s.slice(0, index + 1));
    }
  };

  const closePreview = () => {
    const p = previewState();
    if (p) URL.revokeObjectURL(p.url);
    setPreviewState(null);
  };

  const handleDeletePublicLink = async (share: PublicShareItem) => {
    const confirmed = await openConfirm({
      title: 'Delete Public Link',
      message: `Delete the public link for "${share.filename}"? Anyone with this link will lose access.`,
      confirmText: 'Delete Link',
      type: 'danger',
    });
    if (!confirmed) return;
    try {
      await api.deletePublicShare(share.token);
      toast.success('Public link deleted');
      loadAll();
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete link');
    }
  };

  const handleRevokeUserShare = async (share: UserShareItem) => {
    const confirmed = await openConfirm({
      title: 'Revoke Access',
      message: `Remove @${share.recipientUsername}'s access to "${share.filename}"?`,
      confirmText: 'Revoke',
      type: 'danger',
    });
    if (!confirmed) return;
    try {
      await api.revokeUserShare(share.fileId, share.recipientId);
      toast.success(`Access revoked for @${share.recipientUsername}`);
      loadAll();
    } catch (err: any) {
      toast.error(err.message || 'Failed to revoke access');
    }
  };

  const copyPublicLink = async (token: string) => {
    try {
      await navigator.clipboard.writeText(`${window.location.origin}/share/${token}`);
      toast.success('Link copied to clipboard');
    } catch {
      toast.error('Failed to copy link');
    }
  };

  return (
    <div class="animate-sv-rise space-y-5">

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div class="flex items-center justify-between">
        <div>
          <h2 class="text-xl font-bold text-white">Sharing</h2>
          <p class="text-sm text-gray-400 mt-0.5">Files shared with you and shares you've created</p>
        </div>
        <button
          type="button"
          onClick={() => loadAll()}
          class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700/60 transition-colors cursor-pointer"
          title="Refresh"
          aria-label="Refresh"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>

      {/* ── Tabs ────────────────────────────────────────────────────────────── */}
      <div class="flex gap-1 p-1 bg-gray-800/60 rounded-xl border border-gray-700/50">
        <button
          type="button"
          onClick={() => { setTab('received'); setFolderStack([]); }}
          class={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-sm font-medium transition-all cursor-pointer ${
            tab() === 'received'
              ? 'bg-primary-600/30 text-primary-200 ring-1 ring-primary-500/40'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
          Shared with me
          <Show when={!isLoading() && sharedWithMe().length > 0}>
            <span class="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-primary-500/20 text-primary-300">
              {sharedWithMe().length}
            </span>
          </Show>
        </button>

        <button
          type="button"
          onClick={() => setTab('sent')}
          class={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-sm font-medium transition-all cursor-pointer ${
            tab() === 'sent'
              ? 'bg-primary-600/30 text-primary-200 ring-1 ring-primary-500/40'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
          </svg>
          My shares
          <Show when={!isLoading() && (userShares().length + publicShares().length) > 0}>
            <span class="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-primary-500/20 text-primary-300">
              {userShares().length + publicShares().length}
            </span>
          </Show>
        </button>
      </div>

      {/* ── Loading ─────────────────────────────────────────────────────────── */}
      <Show when={isLoading()}>
        <div class="flex items-center justify-center py-16">
          <div class="flex flex-col items-center gap-3">
            <div class="animate-spin rounded-full h-10 w-10 border-2 border-primary-500/30 border-t-primary-500" />
            <span class="text-sm text-gray-400">Loading…</span>
          </div>
        </div>
      </Show>

      {/* ═══════════════════════════ RECEIVED TAB ════════════════════════════ */}
      <Show when={!isLoading() && tab() === 'received'}>

        {/* Breadcrumb navigation */}
        <Show when={folderStack().length > 0}>
          <nav class="flex items-center gap-1 text-sm flex-wrap" aria-label="Folder navigation">
            <button
              type="button"
              onClick={() => navigateToBreadcrumb(-1)}
              class="text-primary-400 hover:text-primary-300 transition-colors cursor-pointer"
            >
              Shared with me
            </button>
            <For each={folderStack()}>
              {(crumb, i) => (
                <>
                  <svg class="w-3 h-3 text-gray-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                  </svg>
                  <Show
                    when={i() < folderStack().length - 1}
                    fallback={<span class="text-white font-medium truncate max-w-[160px]">{crumb.name}</span>}
                  >
                    <button
                      type="button"
                      onClick={() => navigateToBreadcrumb(i())}
                      class="text-primary-400 hover:text-primary-300 transition-colors cursor-pointer truncate max-w-[120px]"
                    >
                      {crumb.name}
                    </button>
                  </Show>
                </>
              )}
            </For>
          </nav>
        </Show>

        <Show
          when={visibleItems().length > 0}
          fallback={
            <Show
              when={folderStack().length > 0}
              fallback={
                <div class="text-center py-16">
                  <svg class="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                  <h3 class="text-lg font-medium text-gray-300 mb-1">Nothing shared with you yet</h3>
                  <p class="text-sm text-gray-500">When someone shares a file with you, it appears here</p>
                </div>
              }
            >
              <div class="text-center py-10">
                <p class="text-sm text-gray-400">This folder is empty</p>
              </div>
            </Show>
          }
        >
          <div class="space-y-1.5">
            <For each={visibleItems()}>
              {(item) => {
                const busy = () => busyFileId() === item.fileId;
                const canPreview = () => !item.isFolder && isPreviewableFile(item.filename);

                return (
                  <div class="flex items-center gap-3 p-3.5 bg-gray-800/40 border border-gray-700/50 rounded-xl hover:bg-gray-800/60 transition-colors group">
                    {/* Click folder to enter */}
                    <Show
                      when={item.isFolder}
                      fallback={<ItemIcon isFolder={false} />}
                    >
                      <button
                        type="button"
                        onClick={() => handleEnterFolder(item)}
                        class="shrink-0 cursor-pointer hover:scale-110 transition-transform"
                        title="Open folder"
                        aria-label="Open folder"
                      >
                        <FolderIcon />
                      </button>
                    </Show>

                    <div
                      class={`flex-1 min-w-0 ${item.isFolder ? 'cursor-pointer' : ''}`}
                      onClick={() => item.isFolder && handleEnterFolder(item)}
                    >
                      <p class={`text-sm font-medium truncate ${item.isFolder ? 'text-white hover:text-primary-300 transition-colors' : 'text-white'}`}>
                        {item.filename}
                      </p>
                      <div class="flex items-center gap-2 mt-0.5 text-xs text-gray-400 flex-wrap">
                        <span class="flex items-center gap-1">
                          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                          </svg>
                          @{item.ownerUsername}
                        </span>
                        <Show when={!item.isFolder}>
                          <span>·</span>
                          <span>{formatSize(item.fileSize)}</span>
                        </Show>
                        <span>·</span>
                        <span>{formatRelative(item.sharedAt)}</span>
                      </div>
                    </div>

                    <div class="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                      {/* Folder: enter button */}
                      <Show when={item.isFolder}>
                        <button
                          type="button"
                          onClick={() => handleEnterFolder(item)}
                          class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors cursor-pointer"
                          title="Open folder"
                          aria-label="Open folder"
                        >
                          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                          </svg>
                        </button>
                      </Show>

                      {/* File: preview */}
                      <Show when={canPreview()}>
                        <button
                          type="button"
                          disabled={busy()}
                          onClick={() => handlePreview(item)}
                          class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors cursor-pointer disabled:opacity-50"
                          title="Preview"
                          aria-label="Preview"
                        >
                          <Show when={busy()} fallback={
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                            </svg>
                          }><SpinnerIcon /></Show>
                        </button>
                      </Show>

                      {/* File: download */}
                      <Show when={!item.isFolder}>
                        <button
                          type="button"
                          disabled={busy()}
                          onClick={() => handleDownload(item)}
                          class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors cursor-pointer disabled:opacity-50"
                          title="Download"
                          aria-label="Download"
                        >
                          <Show when={busy()} fallback={
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                            </svg>
                          }><SpinnerIcon /></Show>
                        </button>
                      </Show>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </Show>

      {/* ═══════════════════════════ SENT TAB ════════════════════════════════ */}
      <Show when={!isLoading() && tab() === 'sent'}>

        {/* Stats */}
        <div class="grid grid-cols-3 gap-3">
          <div class="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4">
            <div class="text-2xl font-bold text-primary-400">{stats().userShareCount}</div>
            <div class="text-xs text-gray-400 mt-1">Direct Shares</div>
          </div>
          <div class="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4">
            <div class="text-2xl font-bold text-emerald-400">{stats().activeLinks}</div>
            <div class="text-xs text-gray-400 mt-1">Active Links</div>
          </div>
          <div class="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4">
            <div class="text-2xl font-bold text-white">{stats().totalViews}</div>
            <div class="text-xs text-gray-400 mt-1">Total Views</div>
          </div>
        </div>

        {/* Empty */}
        <Show when={userShares().length === 0 && publicShares().length === 0}>
          <div class="text-center py-12">
            <svg class="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
            </svg>
            <h3 class="text-lg font-medium text-gray-300 mb-1">No shares yet</h3>
            <p class="text-sm text-gray-500">Use the Share button on any file to get started</p>
          </div>
        </Show>

        {/* Direct user shares */}
        <Show when={userShares().length > 0}>
          <div class="space-y-2">
            <h3 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Direct shares</h3>
            <For each={userShares()}>
              {(share) => (
                <div class="flex items-center gap-3 p-3.5 bg-gray-800/40 border border-gray-700/50 rounded-xl hover:bg-gray-800/60 transition-colors group">
                  <ItemIcon isFolder={share.isFolder} />
                  <div class="flex-1 min-w-0">
                    <p class="text-sm font-medium text-white truncate">{share.filename}</p>
                    <div class="flex items-center gap-2 mt-0.5 text-xs text-gray-400">
                      <span class="flex items-center gap-1">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                        </svg>
                        @{share.recipientUsername}
                      </span>
                      <span>·</span>
                      <span>{formatSize(share.fileSize)}</span>
                      <span>·</span>
                      <span>{formatRelative(share.sharedAt)}</span>
                    </div>
                  </div>
                  <div class="shrink-0 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                    <button
                      type="button"
                      onClick={() => handleRevokeUserShare(share)}
                      class="p-2 rounded-lg text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors cursor-pointer"
                      title="Revoke access"
                      aria-label="Revoke access"
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                      </svg>
                    </button>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>

        {/* Public links */}
        <Show when={publicShares().length > 0}>
          <div class="space-y-2">
            <h3 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Public links</h3>
            <For each={publicShares()}>
              {(share) => {
                const expired = () => share.isExpired;
                const accessText = () =>
                  share.maxAccess
                    ? `${share.accessCount} / ${share.maxAccess} views`
                    : `${share.accessCount} views`;

                return (
                  <div class={`flex items-center gap-3 p-3.5 border rounded-xl transition-colors group ${
                    expired()
                      ? 'bg-gray-800/20 border-gray-700/30 opacity-60'
                      : 'bg-gray-800/40 border-gray-700/50 hover:bg-gray-800/60'
                  }`}>
                    <ItemIcon isFolder={share.isFolder} />
                    <div class="flex-1 min-w-0">
                      <div class="flex items-center gap-2">
                        <span class="text-sm font-medium text-white truncate">{share.filename}</span>
                        <span class={`px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded-full ${
                          expired()
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        }`}>
                          {expired() ? 'Inactive' : 'Active'}
                        </span>
                      </div>
                      <div class="flex items-center gap-2 mt-0.5 text-xs text-gray-400 flex-wrap">
                        <span class="flex items-center gap-1">
                          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                          </svg>
                          {accessText()}
                        </span>
                        <span>·</span>
                        <span>{formatSize(share.fileSize)}</span>
                        <span>·</span>
                        <span>Expires {share.expiresAt ? formatRelative(share.expiresAt) : '—'}</span>
                      </div>
                    </div>
                    <div class="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                      <Show when={!expired()}>
                        <button
                          type="button"
                          onClick={() => copyPublicLink(share.token)}
                          class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors cursor-pointer"
                          title="Copy link"
                          aria-label="Copy link"
                        >
                          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                          </svg>
                        </button>
                      </Show>
                      <button
                        type="button"
                        onClick={() => handleDeletePublicLink(share)}
                        class="p-2 rounded-lg text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors cursor-pointer"
                        title="Revoke Link"
                        aria-label="Revoke Link"
                      >
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                        <span class="sr-only">Revoke Link</span>
                      </button>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </Show>

      {/* ═════════════════════════ PREVIEW MODAL ═════════════════════════════ */}
      {/* ═════════════════════════ PREVIEW MODAL ═════════════════════════════ */}
      <Portal>
        <Show when={previewState()}>
          {(p) => (
            <div
              class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-2 sm:p-4 sv-modal-overlay"
              onClick={closePreview}
            >
              <div
                class="bg-gray-800 rounded-xl max-w-5xl max-h-[calc(100vh-2rem)] w-full overflow-hidden sv-modal-panel"
                onClick={(e) => e.stopPropagation()}
              >
                {/* Modal Header */}
                <div class="flex items-center justify-between px-4 py-3 border-b border-gray-700">
                  <h3 class="text-lg font-medium text-white truncate">{p().filename}</h3>
                  <div class="flex items-center gap-2">
                    <a
                      href={p().url}
                      download={p().filename}
                      class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors"
                      title="Download"
                      aria-label="Download"
                    >
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                    </a>
                    <button
                      onClick={closePreview}
                      class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors"
                      aria-label="Close preview"
                    >
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </div>
                
                {/* Modal Content */}
                <div class="p-4 overflow-auto max-h-[calc(90vh-60px)]">
                  {/* Image Preview */}
                  <Show when={p().mimeType.startsWith('image/')}>
                    <img src={p().url} alt={p().filename} class="max-w-full max-h-[70vh] mx-auto rounded-lg" />
                  </Show>

                  {/* Video Preview */}
                  <Show when={p().mimeType.startsWith('video/')}>
                    <video src={p().url} controls class="max-w-full max-h-[70vh] mx-auto rounded-lg" />
                  </Show>

                  {/* Audio Preview */}
                  <Show when={p().mimeType.startsWith('audio/')}>
                    <div class="flex flex-col items-center gap-4 py-8">
                      <svg class="w-24 h-24 text-gray-500" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>
                      </svg>
                      <audio src={p().url} controls class="w-full max-w-md" />
                    </div>
                  </Show>

                  {/* PDF Preview */}
                  <Show when={p().mimeType === 'application/pdf'}>
                    <iframe src={p().url} class="w-full h-[70vh] rounded-lg bg-white" title={p().filename} />
                  </Show>

                  {/* CSV Preview */}
                  <Show when={p().mimeType === 'text/csv'}>
                    <CsvPreview url={p().url} />
                  </Show>

                  {/* Excel Preview */}
                  <Show when={p().mimeType.includes('spreadsheet') || p().mimeType.includes('excel')}>
                    <ExcelPreview url={p().url} />
                  </Show>

                  {/* Word Preview */}
                  <Show when={p().mimeType.includes('wordprocessingml') || p().mimeType === 'application/msword'}>
                    <WordPreview url={p().url} />
                  </Show>

                  {/* Text/Code Preview */}
                  <Show when={
                    (p().mimeType.startsWith('text/') && p().mimeType !== 'text/csv') || 
                    p().mimeType === 'application/json'
                  }>
                    <DashboardTextPreview url={p().url} />
                  </Show>
                </div>
              </div>
            </div>
          )}
        </Show>
      </Portal>
    </div>
  );
}
