import { createSignal, createEffect, Show, For, onMount, createMemo } from 'solid-js';
import { formatSize } from '../../lib/format';
import { ROUTES } from '../../lib/routes';
import { publicRequestJson, publicRequestRaw, ApiError } from '../../lib/api';
import { getFileExtension } from '../../lib/files';
import { logger } from '../../lib/logger';
import { awaitMinElapsed, MIN_CONTENT_LOAD_MS } from '../../lib/motion';
import { blobFromBlobUrlFetchResponse, prefersExplicitSaveStep, saveBlobToDevice } from '../../lib/downloadBlob';
import { toast } from '../../stores/toast';
import BlobSavePrompt from '../BlobSavePrompt';
import { CsvPreview, ExcelPreview, WordPreview, getPreviewMimeType, isPreviewableFile } from '../FilePreview';
import {
  base64ToArrayBuffer,
  importFileKey,
  decryptSharedFile,
  isEncryptedFilename,
  decryptEncryptedFilename,
} from './publicShareCrypto';

interface SharedFile {
  id: string;
  filename: string;
  fileSize: number;
  encryptedKey: string;
  iv: string;
  isFolder?: boolean;
}

interface FolderItem {
  id: string;
  filename: string;
  isFolder: boolean;
  fileSize?: number;
  encryptedKey?: string;
  iv?: string;
  children?: FolderItem[];
}

interface SharedFolder {
  id: string;
  filename: string;
  children: FolderItem[];
}

export default function PublicShare() {
  // Single file state
  const [file, setFile] = createSignal<SharedFile | null>(null);
  // Folder state
  const [folder, setFolder] = createSignal<SharedFolder | null>(null);
  const [isFolder, setIsFolder] = createSignal(false);
  // Path within shared folder only - NO parent access. [subfolder1, subfolder2] = we're in subfolder2
  const [folderPath, setFolderPath] = createSignal<FolderItem[]>([]);
  const [viewMode, setViewMode] = createSignal<'grid' | 'list'>('grid');
  const [sortBy, setSortBy] = createSignal<'name' | 'type'>('name');
  const [sortOrder, setSortOrder] = createSignal<'asc' | 'desc'>('asc');
  const [filterType, setFilterType] = createSignal<'all' | 'folders' | 'files'>('all');
  const [openMenuId, setOpenMenuId] = createSignal<string | null>(null);
  
  const [error, setError] = createSignal<string | null>(null);
  const [isLoading, setIsLoading] = createSignal(true);
  const [isDownloading, setIsDownloading] = createSignal(false);
  const [downloadingFileId, setDownloadingFileId] = createSignal<string | null>(null);
  const [pendingBlobSave, setPendingBlobSave] = createSignal<{ blob: Blob; filename: string } | null>(null);
  const [decryptionKey, setDecryptionKey] = createSignal<string | null>(null);
  const [decryptionIv, setDecryptionIv] = createSignal<string | null>(null);
  
  // Preview state (for single files)
  const [previewUrl, setPreviewUrl] = createSignal<string | null>(null);
  const [previewMimeType, setPreviewMimeType] = createSignal<string | null>(null);
  const [isLoadingPreview, setIsLoadingPreview] = createSignal(false);
  const [textContent, setTextContent] = createSignal<string | null>(null);
  
  // Get token from URL path and key from fragment
  const getToken = () => {
    const path = window.location.pathname;
    const match = path.match(/\/share\/([a-zA-Z0-9-]+)/);
    return match ? match[1] : null;
  };
  
  // Extract key and IV from URL fragment (format: #key:iv)
  const parseFragment = () => {
    const hash = window.location.hash.slice(1); // Remove #
    if (!hash) return null;
    if (hash.startsWith('bundle=')) {
      const enc = hash.slice('bundle='.length);
      try {
        const padded = enc.replace(/-/g, '+').replace(/_/g, '/');
        const json = decodeURIComponent(escape(atob(padded)));
        const parsed = JSON.parse(json) as { v: number; keys: Record<string, { k: string; iv?: string }> };
        if (parsed && parsed.v === 1 && parsed.keys && typeof parsed.keys === 'object') {
          return { bundle: parsed.keys } as const;
        }
      } catch {
        return null;
      }
      return null;
    }
    const parts = hash.split(':');
    if (parts.length === 2) return { key: parts[0], iv: parts[1] };
    return null;
  };
  
  const token = getToken();

  // When user clicks browser back from share, go to home instead of previous page (e.g. folder view)
  onMount(() => {
    const handlePopState = () => {
      window.location.href = ROUTES.home;
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  });

  // Close menu when clicking outside
  createEffect(() => {
    if (!openMenuId()) return;
    const close = () => setOpenMenuId(null);
    const t = setTimeout(() => document.addEventListener('click', close), 0);
    return () => {
      clearTimeout(t);
      document.removeEventListener('click', close);
    };
  });
  
  const goToHome = () => {
    window.location.href = ROUTES.home;
  };
  
  const getMimeType = (filename: string): string => {
    return getPreviewMimeType(filename);
  };
  
  const isPreviewable = (filename: string): boolean => {
    return isPreviewableFile(filename);
  };
  
  createEffect(() => {
    void (async () => {
      const t0 = Date.now();
      // Parse the fragment for decryption key (single file) or bundle (folder share)
      const fragment = parseFragment();
      if (fragment) {
        if ('key' in fragment) {
          setDecryptionKey(fragment.key);
          setDecryptionIv(fragment.iv);
        } else {
          setDecryptionKey(null);
          setDecryptionIv(null);
        }
      }

      if (!token) {
        setError('Invalid share link');
        await awaitMinElapsed(t0, MIN_CONTENT_LOAD_MS);
        setIsLoading(false);
        return;
      }

      try {
        type PublicMeta = {
          isFolder?: boolean;
          folder?: { id: string; filename?: string; children?: FolderItem[] };
          file?: SharedFile;
          msg?: string;
        };
        const data = await publicRequestJson<PublicMeta>(`/public/${token}`);

        if (data.isFolder) {
          setIsFolder(true);
          const folderData = data.folder;
          if (!folderData) {
            setError('Invalid share data');
          } else {
            // Decrypt encrypted filenames in the folder tree using the per-item key bundle (when present).
            const decryptFolderItems = async (items: FolderItem[]): Promise<FolderItem[]> => {
              return Promise.all(items.map(async (item) => {
                let decryptedName = item.filename;
                if (isEncryptedFilename(item.filename) && fragment && 'bundle' in fragment) {
                  const entry = fragment.bundle[item.id];
                  if (entry?.k) {
                    try {
                      const itemKey = await importFileKey(entry.k);
                      decryptedName = await decryptEncryptedFilename(item.filename, itemKey);
                    } catch { /* keep raw */ }
                  }
                } else if (isEncryptedFilename(item.filename) && fragment && 'key' in fragment) {
                  // Back-compat: treat as single-key share
                  try {
                    const itemKey = await importFileKey(fragment.key);
                    decryptedName = await decryptEncryptedFilename(item.filename, itemKey);
                  } catch { /* keep raw */ }
                }
                const children = item.children ? await decryptFolderItems(item.children) : undefined;
                return { ...item, filename: decryptedName, children };
              }));
            };

            const folderName = folderData.filename || 'Folder';
            const children = Array.isArray(folderData.children) ? await decryptFolderItems(folderData.children) : [];

            setFolder({ id: folderData.id, filename: folderName, children });
          }
        } else {
          setIsFolder(false);
          const sharedFile = data.file;
          if (!sharedFile) {
            setError('Invalid share data');
          } else {
            // Decrypt encrypted filename using the key from the URL fragment
            let displayName = sharedFile.filename;
            if (fragment && isEncryptedFilename(sharedFile.filename)) {
              try {
                const fileKey = await importFileKey(fragment.key);
                displayName = await decryptEncryptedFilename(sharedFile.filename, fileKey);
              } catch { /* keep raw */ }
            }
            const decryptedFile = { ...sharedFile, filename: displayName };
            setFile(decryptedFile);
            if (fragment && isPreviewable(decryptedFile.filename)) {
              loadPreview(fragment.key, fragment.iv, decryptedFile.filename);
            }
          }
        }
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'Failed to load shared content');
      } finally {
        await awaitMinElapsed(t0, MIN_CONTENT_LOAD_MS);
        setIsLoading(false);
      }
    })();
  });
  
  const loadPreview = async (key: string, iv: string, filename: string) => {
    if (!token) return;

    const t0 = Date.now();
    setIsLoadingPreview(true);

    try {
      const response = await publicRequestRaw(`/public/${token}/download`);
      const encryptedData = await response.arrayBuffer();
      const cryptoKey = await importFileKey(key);
      const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
      const decryptedData = await decryptSharedFile(encryptedData, cryptoKey, ivBytes);
      
      const mimeType = getMimeType(filename);
      setPreviewMimeType(mimeType);
      
      // For text files (except CSV), read as text
      if ((mimeType.startsWith('text/') && mimeType !== 'text/csv') || mimeType === 'application/json') {
        const text = new TextDecoder().decode(decryptedData);
        setTextContent(text);
      } else {
        // For binary files (images, video, audio, PDF, CSV, Excel, Word), create blob URL
        const blob = new Blob([decryptedData], { type: mimeType });
        const url = URL.createObjectURL(blob);
        setPreviewUrl(url);
      }
    } catch (err) {
      logger.error('Preview error:', err);
      // Don't show error, just don't show preview
    } finally {
      await awaitMinElapsed(t0, MIN_CONTENT_LOAD_MS);
      setIsLoadingPreview(false);
    }
  };
  
  const handleDownload = async () => {
    if (!token || !file()) return;

    if (pendingBlobSave()) {
      toast.warning('Finish saving the current file or cancel first.');
      return;
    }

    setIsDownloading(true);

    try {
      let blob: Blob;

      if (previewUrl()) {
        const mime = previewMimeType() || getMimeType(file()!.filename);
        const r = await fetch(previewUrl()!);
        blob = blobFromBlobUrlFetchResponse(await r.blob(), mime);
      } else if (textContent()) {
        blob = new Blob([textContent()!], { type: previewMimeType() || 'text/plain' });
      } else {
        const response = await publicRequestRaw(`/public/${token}/download`);
        const key = decryptionKey();
        const iv = decryptionIv();

        if (key && iv) {
          const encryptedData = await response.arrayBuffer();
          const cryptoKey = await importFileKey(key);
          const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
          const decryptedData = await decryptSharedFile(encryptedData, cryptoKey, ivBytes);
          const mimeType = getMimeType(file()!.filename);
          blob = new Blob([decryptedData], { type: mimeType });
        } else {
          blob = await response.blob();
        }
      }

      const fname = file()!.filename;
      if (prefersExplicitSaveStep()) {
        setPendingBlobSave({ blob, filename: fname });
      } else {
        await saveBlobToDevice(blob, fname);
      }
    } catch (err: any) {
      logger.error('Download error:', err);
      setError(err.message || 'Download failed - the link may be incomplete');
    } finally {
      setIsDownloading(false);
    }
  };

  // Download a file from a shared folder
  const handleFolderFileDownload = async (item: FolderItem) => {
    if (!token || item.isFolder) return;

    if (pendingBlobSave()) {
      toast.warning('Finish saving the current file or cancel first.');
      return;
    }

    setDownloadingFileId(item.id);

    try {
      const response = await publicRequestRaw(`/public/${token}/file/${item.id}/download`);
      const encryptedData = await response.arrayBuffer();

      // If a bundle key is present, decrypt the file content in-browser; otherwise download encrypted bytes.
      const fragment = parseFragment();
      let blob: Blob;
      if (fragment && 'bundle' in fragment) {
        const entry = fragment.bundle[item.id];
        if (entry?.k && (entry.iv || item.iv)) {
          const cryptoKey = await importFileKey(entry.k);
          const ivBytes = new Uint8Array(base64ToArrayBuffer(entry.iv || item.iv!));
          const decrypted = await decryptSharedFile(encryptedData, cryptoKey, ivBytes);
          blob = new Blob([decrypted], { type: 'application/octet-stream' });
        } else {
          blob = new Blob([encryptedData], { type: 'application/octet-stream' });
        }
      } else {
        blob = new Blob([encryptedData], { type: 'application/octet-stream' });
      }

      if (prefersExplicitSaveStep()) {
        setPendingBlobSave({ blob, filename: item.filename });
      } else {
        await saveBlobToDevice(blob, item.filename);
      }
    } catch (err: any) {
      logger.error('Download error:', err);
      setError(err.message || 'Download failed');
    } finally {
      setDownloadingFileId(null);
    }
  };
  
  // Visible items: at root = folder().children, else = last folder in path's children
  const visibleItems = () => {
    const f = folder();
    const path = folderPath();
    if (!f) return [];
    if (path.length === 0) return f.children || [];
    const last = path[path.length - 1];
    return (last.children || []);
  };

  // Filtered and sorted items (Drive-style)
  const displayedItems = createMemo(() => {
    const items = [...visibleItems()];
    let filtered = items;
    if (filterType() === 'folders') filtered = items.filter((i) => i.isFolder);
    else if (filterType() === 'files') filtered = items.filter((i) => !i.isFolder);
    const sorted = [...filtered].sort((a, b) => {
      const cmp = sortBy() === 'name'
        ? (a.filename.localeCompare(b.filename, undefined, { sensitivity: 'base' }))
        : ((a.isFolder ? 1 : 0) - (b.isFolder ? 1 : 0)) || a.filename.localeCompare(b.filename);
      return sortOrder() === 'asc' ? cmp : -cmp;
    });
    return sorted;
  });

  // Navigate into subfolder (only within shared folder - no parent access)
  const navigateIntoFolder = (item: FolderItem) => {
    if (!item.isFolder || !item.children) return;
    setFolderPath([...folderPath(), item]);
  };

  // Navigate via breadcrumb - index 0 = root, index i = go to path[i-1]
  const navigateToBreadcrumb = (index: number) => {
    setFolderPath(folderPath().slice(0, index));
  };

  // Shared folder icon (folder + person) - Drive style. size: 'sm' for header, 'md' default
  const getSharedFolderIcon = (filename: string, isFolder: boolean, size: 'sm' | 'md' = 'md') => {
    const iconCls = size === 'sm' ? 'w-5 h-5' : 'w-10 h-10';
    const badgeCls = size === 'sm' ? 'w-2.5 h-2.5' : 'w-4 h-4';
    if (isFolder) {
      return (
        <div class="relative inline-flex">
          <svg class={`${iconCls} text-amber-400`} fill="currentColor" viewBox="0 0 24 24">
            <path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" />
          </svg>
          <svg class={`absolute bottom-0 right-0 ${badgeCls} text-blue-400 bg-[#111111] rounded-full`} fill="currentColor" viewBox="0 0 24 24">
            <path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z" />
          </svg>
        </div>
      );
    }
    const ext = getFileExtension(filename);
    const iconColors: Record<string, string> = {
      pdf: 'text-red-500', jpg: 'text-red-500', jpeg: 'text-red-500', png: 'text-red-500', gif: 'text-red-500', webp: 'text-red-500',
      doc: 'text-blue-500', docx: 'text-blue-500', xls: 'text-green-500', xlsx: 'text-green-500',
      mp4: 'text-pink-500', mov: 'text-pink-500', webm: 'text-pink-500',
      mp3: 'text-orange-500', wav: 'text-orange-500', zip: 'text-yellow-600', rar: 'text-yellow-600',
    };
    return (
      <svg class={`${iconCls} ${iconColors[ext] || 'text-gray-400'}`} fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
      </svg>
    );
  };
  
  // Render preview content based on MIME type
  const renderPreview = () => {
    const mime = previewMimeType();
    const url = previewUrl();
    const text = textContent();
    
    if (!mime) return null;
    
    if (mime.startsWith('image/')) {
      return (
        <img 
          src={url!} 
          alt={file()?.filename}
          class="max-w-full max-h-[60vh] mx-auto rounded-lg shadow-lg"
        />
      );
    }
    
    if (mime.startsWith('video/')) {
      return (
        <video 
          src={url!} 
          controls 
          class="max-w-full max-h-[60vh] mx-auto rounded-lg shadow-lg"
        />
      );
    }
    
    if (mime.startsWith('audio/')) {
      return (
        <div class="flex flex-col items-center gap-4 py-4">
          <svg class="w-20 h-20 text-gray-500" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>
          </svg>
          <audio src={url!} controls class="w-full max-w-sm" />
        </div>
      );
    }
    
    if (mime === 'application/pdf') {
      return (
        <iframe 
          src={url!} 
          class="w-full h-[60vh] rounded-lg bg-white"
        />
      );
    }
    
    // CSV Preview
    if (mime === 'text/csv') {
      return <CsvPreview url={url!} />;
    }
    
    // Excel Preview
    if (mime.includes('spreadsheet') || mime.includes('excel')) {
      return <ExcelPreview url={url!} />;
    }
    
    // Word Preview
    if (mime.includes('wordprocessingml') || mime === 'application/msword') {
      return <WordPreview url={url!} />;
    }
    
    // Text/Code Preview (but not CSV)
    if ((mime.startsWith('text/') && mime !== 'text/csv') || mime === 'application/json') {
      return (
        <pre class="bg-gray-900 p-4 rounded-lg overflow-auto max-h-[60vh] text-sm text-gray-300 font-mono whitespace-pre-wrap text-left">
          {text}
        </pre>
      );
    }
    
    return null;
  };
  
  // Single full-page Drive-style layout for all share types (folder + file + loading + error)
  const showFolderView = () => isFolder() && folder() && !isLoading() && !error();
  const breadcrumbTitle = () => {
    if (isLoading()) return 'Loading...';
    if (error()) return 'Error';
    if (folder()) return folder()!.filename;
    if (file()) return file()!.filename;
    return 'Shared';
  };

  return (
    <div class="min-h-screen bg-[#111111] flex flex-col">
      {/* Header - same style as My Drive / shared folder */}
      <header class="sticky top-0 z-20 bg-[#111111] border-b border-gray-800">
        <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
          <div class="flex items-center gap-2 min-w-0 flex-1">
            <button
              onClick={goToHome}
              class="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-full transition-colors shrink-0"
              title="Home"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
              </svg>
            </button>
            <div class="flex items-center gap-1.5 min-w-0 overflow-hidden">
              <span class="text-gray-400 text-sm">Shared with me</span>
              <Show when={showFolderView()} fallback={
                <>
                  <svg class="w-4 h-4 text-gray-600 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" />
                  </svg>
                  <span class="text-white font-medium text-sm truncate">{breadcrumbTitle()}</span>
                </>
              }>
                <svg class="w-4 h-4 text-gray-600 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" />
                </svg>
                <button onClick={() => navigateToBreadcrumb(0)} class={`text-sm truncate transition-colors flex items-center gap-1 ${folderPath().length === 0 ? 'text-white font-medium' : 'text-gray-400 hover:text-white'}`}>
                  {folderPath().length === 0 && (
                    <svg class="w-4 h-4 text-blue-400 shrink-0" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z" />
                    </svg>
                  )}
                  {folder()!.filename}
                </button>
                <For each={folderPath()}>
                  {(item, i) => (
                    <>
                      <svg class="w-4 h-4 text-gray-600 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" />
                      </svg>
                      <button onClick={() => navigateToBreadcrumb(i() + 1)} class={`text-sm truncate max-w-[140px] transition-colors flex items-center gap-1 ${i() === folderPath().length - 1 ? 'text-white font-medium' : 'text-gray-400 hover:text-white'}`}>
                        {i() === folderPath().length - 1 && (
                          <svg class="w-4 h-4 text-blue-400 shrink-0" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z" />
                          </svg>
                        )}
                        {item.filename}
                      </button>
                    </>
                  )}
                </For>
              </Show>
            </div>
          </div>
          <Show when={showFolderView()}>
            <div class="flex items-center gap-1 shrink-0">
              <button
                onClick={() => setViewMode('list')}
                class={`p-2 rounded-lg transition-colors ${viewMode() === 'list' ? 'bg-primary-600/20 text-primary-400' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
                title="List view"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                </svg>
              </button>
              <button
                onClick={() => setViewMode('grid')}
                class={`p-2 rounded-lg transition-colors ${viewMode() === 'grid' ? 'bg-primary-600/20 text-primary-400' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
                title="Grid view"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                </svg>
              </button>
            </div>
          </Show>
        </div>
      </header>

      {/* Toolbar - only for folder view */}
      <Show when={showFolderView()}>
        <div class="bg-[#111111] border-b border-gray-800">
          <div class="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center gap-2">
            <select
              value={filterType()}
              onChange={(e) => setFilterType(e.target.value as any)}
              class="px-3 py-1.5 bg-gray-800/80 border border-gray-700 rounded-lg text-gray-300 text-sm focus:outline-none focus:ring-1 focus:ring-primary-500"
            >
              <option value="all">Type</option>
              <option value="folders">Folders</option>
              <option value="files">Files</option>
            </select>
            <select
              value={sortBy()}
              onChange={(e) => setSortBy(e.target.value as any)}
              class="px-3 py-1.5 bg-gray-800/80 border border-gray-700 rounded-lg text-gray-300 text-sm focus:outline-none focus:ring-1 focus:ring-primary-500"
            >
              <option value="name">Name</option>
              <option value="type">Type</option>
            </select>
            <button
              onClick={() => setSortOrder(sortOrder() === 'asc' ? 'desc' : 'asc')}
              class="p-1.5 text-gray-400 hover:text-white rounded-lg transition-colors"
              title={sortOrder() === 'asc' ? 'Ascending' : 'Descending'}
            >
              <svg class={`w-4 h-4 transition-transform ${sortOrder() === 'desc' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7" />
              </svg>
            </button>
          </div>
        </div>
      </Show>

      {/* Main content */}
      <main class="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        <Show when={isLoading()}>
          <div class="flex flex-col items-center justify-center py-24">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mb-4"></div>
            <p class="text-gray-400">Loading shared content...</p>
          </div>
        </Show>

        <Show when={error()}>
          <div class="flex flex-col items-center justify-center py-24 text-center">
            <div class="w-16 h-16 bg-red-500/20 rounded-full flex items-center justify-center mb-4">
              <svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
            <h2 class="text-xl font-semibold text-white mb-2">Link Unavailable</h2>
            <p class="text-gray-400 mb-6">{error()}</p>
            <button
              onClick={goToHome}
              class="px-6 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm"
            >
              Go to SecureVault
            </button>
          </div>
        </Show>

        {/* Folder view - grid/list like My Drive */}
        <Show when={showFolderView()}>
          <Show when={displayedItems().length === 0}>
            <div class="flex flex-col items-center justify-center py-24 text-gray-500">
              <div class="w-20 h-20 rounded-2xl bg-gray-800/80 flex items-center justify-center mb-4">
                <svg class="w-10 h-10 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
              </div>
              <p class="text-base">This folder is empty</p>
            </div>
          </Show>

          <Show when={displayedItems().length > 0}>
            <Show when={viewMode() === 'grid'} fallback={
              <div class="space-y-0.5">
                <For each={displayedItems()}>
                  {(item) => (
                    <div
                      class={`flex items-center gap-4 px-4 py-3 rounded-xl transition-colors ${item.isFolder ? 'cursor-pointer hover:bg-gray-800/80' : ''}`}
                      onClick={() => item.isFolder && navigateIntoFolder(item)}
                    >
                      <div class="w-10 h-10 flex items-center justify-center shrink-0">
                        {getSharedFolderIcon(item.filename, item.isFolder)}
                      </div>
                      <div class="flex-1 min-w-0">
                        <p class="text-white truncate">{item.filename}</p>
                        <p class="text-gray-500 text-sm">{item.isFolder ? 'Folder' : formatSize(item.fileSize, { unset: '0 B', zero: '0 B' })}</p>
                      </div>
                      {!item.isFolder && (
                        <button
                          onClick={(e) => { e.stopPropagation(); handleFolderFileDownload(item); }}
                          disabled={downloadingFileId() === item.id}
                          class="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg shrink-0"
                        >
                          {downloadingFileId() === item.id ? (
                            <svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" /><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                          ) : (
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                          )}
                        </button>
                      )}
                      <div class="relative">
                        <button onClick={(e) => { e.stopPropagation(); setOpenMenuId(openMenuId() === item.id ? null : item.id); }} class="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg">
                          <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z" /></svg>
                        </button>
                        <Show when={openMenuId() === item.id}>
                          <div class="absolute right-0 top-full mt-1 w-48 py-1 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-10">
                            {!item.isFolder && (
                              <button
                                type="button"
                                disabled={!!pendingBlobSave() || downloadingFileId() === item.id}
                                onClick={(e) => { e.stopPropagation(); handleFolderFileDownload(item); setOpenMenuId(null); }}
                                class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                              >
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                                Download
                              </button>
                            )}
                          </div>
                        </Show>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            }>
              <div class="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-6 xl:grid-cols-8 gap-4">
                <For each={displayedItems()}>
                  {(item) => (
                    <div
                      class={`group relative flex flex-col rounded-xl bg-[#1e1e1e] overflow-hidden transition-all ${item.isFolder ? 'cursor-pointer hover:ring-1 hover:ring-gray-600' : ''}`}
                      onClick={() => item.isFolder && navigateIntoFolder(item)}
                    >
                      <div class="flex items-center gap-2 px-3 py-2 min-h-0">
                        <div class="w-6 h-6 flex items-center justify-center shrink-0 overflow-hidden">
                          {getSharedFolderIcon(item.filename, item.isFolder, 'sm')}
                        </div>
                        <p class="flex-1 text-sm text-white truncate min-w-0">{item.filename}</p>
                        <button onClick={(e) => { e.stopPropagation(); setOpenMenuId(openMenuId() === item.id ? null : item.id); }} class="p-1 text-gray-400 hover:text-white opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                          <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z" /></svg>
                        </button>
                      </div>
                      <div class="aspect-square bg-[#2a2a2a] flex items-center justify-center p-4">
                        <div class="w-full h-full flex items-center justify-center rounded-lg bg-gray-800/50">
                          {getSharedFolderIcon(item.filename, item.isFolder, 'md')}
                        </div>
                      </div>
                      <Show when={openMenuId() === item.id}>
                        <div class="absolute right-2 top-12 w-40 py-1 bg-[#1e1e1e] border border-gray-700 rounded-lg shadow-xl z-10">
                          {!item.isFolder && (
                            <button
                              type="button"
                              disabled={!!pendingBlobSave() || downloadingFileId() === item.id}
                              onClick={(e) => { e.stopPropagation(); handleFolderFileDownload(item); setOpenMenuId(null); }}
                              class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                            >
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                            Download
                          </button>
                          )}
                        </div>
                      </Show>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </Show>
        </Show>

        {/* Single file view - same full page, content in main */}
        <Show when={!isLoading() && !error() && !isFolder() && file()}>
          <div class="max-w-4xl mx-auto">
            <Show when={isLoadingPreview()}>
              <div class="flex flex-col items-center justify-center py-8 mb-6">
                <div class="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mb-3"></div>
                <p class="text-gray-400 text-sm">Loading preview...</p>
              </div>
            </Show>
            <Show when={!isLoadingPreview() && (previewUrl() || textContent())}>
              <div class="mb-6">{renderPreview()}</div>
            </Show>
            <h2 class="text-xl font-semibold text-white mb-1 break-all">{file()!.filename}</h2>
            <p class="text-gray-400 text-sm mb-6">{formatSize(file()!.fileSize, { unset: '0 B', zero: '0 B' })}</p>
            <button
              type="button"
              onClick={handleDownload}
              disabled={isDownloading() || !!pendingBlobSave()}
              class="w-full max-w-xs py-3 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 rounded-lg text-white font-medium flex items-center justify-center gap-2 transition-colors disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {isDownloading() ? (
                <><svg class="animate-spin h-5 w-5" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" /><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg> Downloading...</>
              ) : (
                <><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg> Download File</>
              )}
            </button>
            <p class="text-gray-500 text-xs mt-4">
              {decryptionKey() ? '🔓 File decrypted securely in your browser.' : '⚠️ Incomplete link - file may download encrypted.'}
            </p>
          </div>
        </Show>
      </main>

      <footer class="py-3 text-center text-gray-600 text-xs border-t border-gray-800">
        🔒 SecureVault • End-to-End Encrypted
      </footer>

      <BlobSavePrompt
        pending={pendingBlobSave()}
        onClose={() => setPendingBlobSave(null)}
      />
    </div>
  );
}
