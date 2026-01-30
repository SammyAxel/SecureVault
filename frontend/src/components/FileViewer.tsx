import { createSignal, createEffect, Show, For } from 'solid-js';
import { useAuth } from '../stores/auth.jsx';
import * as api from '../lib/api';
import type { FileItem } from '../lib/api';
import { toast } from '../stores/toast';
import { SkeletonFileViewer } from './Skeleton';
import { CsvPreview, ExcelPreview, WordPreview, getPreviewMimeType, isPreviewableFile } from './FilePreview';
import {
  getCurrentKeys,
  importEncryptionPrivateKey,
  decryptFile,
  unwrapKey,
  base64ToUint8Array,
} from '../lib/crypto';

interface FileViewerProps {
  uid: string;
  navigate: (path: string) => void;
}

function getMimeType(filename: string): string {
  return getPreviewMimeType(filename);
}

function isPreviewable(filename: string): boolean {
  return isPreviewableFile(filename);
}

export default function FileViewer(props: FileViewerProps) {
  const { user } = useAuth();
  const [isLoading, setIsLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorType, setErrorType] = createSignal<'notfound' | 'unauthorized' | 'error'>('error');
  const [file, setFile] = createSignal<FileItem | null>(null);
  const [folderContents, setFolderContents] = createSignal<FileItem[]>([]);
  const [previewUrl, setPreviewUrl] = createSignal<string | null>(null);
  const [previewMimeType, setPreviewMimeType] = createSignal<string | null>(null);
  const [isDownloading, setIsDownloading] = createSignal(false);
  const [parentPath, setParentPath] = createSignal<Array<{ id: string; uid: string | null; name: string }>>([]);

  // Load file/folder by UID
  const loadFileByUid = async (uid: string) => {
    setIsLoading(true);
    setError(null);
    setPreviewUrl(null); // Clear previous preview
    setFolderContents([]); // Clear previous folder contents
    setParentPath([]); // Clear previous parent path
    
    try {
      const result = await api.getFileByUid(uid);
      
      if (!result.ok) {
        setErrorType('notfound');
        setError('File or folder not found');
        setIsLoading(false);
        return;
      }
      
      setFile(result.file);
      setParentPath(result.parentPath || []);
      
      if (result.file.isFolder) {
        // Load folder contents
        const contents = await api.listFiles(result.file.id);
        setFolderContents(contents.files);
      } else {
        // Load file preview
        await loadPreview(result.file);
      }
    } catch (err: any) {
      console.error('FileViewer: Failed to load:', err);
      if (err.status === 403 || err.message?.includes('403') || err.message?.includes('Access denied')) {
        setErrorType('unauthorized');
        setError('You do not have access to this file');
      } else if (err.status === 404 || err.message?.includes('404') || err.message?.includes('not found')) {
        setErrorType('notfound');
        setError('File or folder not found');
      } else {
        setErrorType('error');
        setError(err.message || 'Failed to load');
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Track UID changes and reload - this handles both initial mount and subsequent navigation
  createEffect(() => {
    const uid = props.uid;
    if (uid) {
      loadFileByUid(uid);
    }
  });

  const loadPreview = async (fileItem: FileItem) => {
    const keys = getCurrentKeys();
    if (!keys) {
      setError('Encryption keys not available. Please log in again.');
      return;
    }

    try {
      const { data, encryptedKey, iv } = await api.downloadFile(fileItem.id);
      const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      const fileKey = await unwrapKey(encryptedKey, privateKey);
      const decrypted = await decryptFile(data, fileKey, base64ToUint8Array(iv));

      const mimeType = getMimeType(fileItem.filename);
      setPreviewMimeType(mimeType);

      const blob = new Blob([decrypted], { type: mimeType });
      const url = URL.createObjectURL(blob);
      setPreviewUrl(url);
    } catch (err: any) {
      console.error('Failed to decrypt file:', err);
      setError('Failed to decrypt file');
    }
  };

  const handleDownload = async () => {
    const f = file();
    if (!f || f.isFolder) return;

    const keys = getCurrentKeys();
    if (!keys) {
      toast.error('Please login again - keys not found');
      return;
    }

    setIsDownloading(true);
    try {
      // Use existing preview if available
      if (previewUrl()) {
        const a = document.createElement('a');
        a.href = previewUrl()!;
        a.download = f.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      } else {
        const { data, encryptedKey, iv } = await api.downloadFile(f.id);
        const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
        const fileKey = await unwrapKey(encryptedKey, privateKey);
        const decrypted = await decryptFile(data, fileKey, base64ToUint8Array(iv));

        const mimeType = getMimeType(f.filename);
        const blob = new Blob([decrypted], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = f.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      toast.error(`Download failed: ${err.message}`);
    } finally {
      setIsDownloading(false);
    }
  };

  const openItem = (item: FileItem) => {
    if (item.uid) {
      props.navigate(`/f/${item.uid}`);
    }
  };

  const goToDrive = () => {
    props.navigate('/');
  };

  // Go back to parent folder
  const goBack = () => {
    const path = parentPath();
    if (path.length > 0) {
      const parent = path[path.length - 1];
      if (parent.uid) {
        props.navigate(`/f/${parent.uid}`);
      } else {
        props.navigate('/');
      }
    } else {
      props.navigate('/');
    }
  };

  // Check if we have a parent folder to go back to
  const hasParentFolder = () => {
    const path = parentPath();
    return path.length > 0 && path[path.length - 1].uid;
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getFileIcon = (filename: string, isFolder: boolean) => {
    if (isFolder) {
      return (
        <svg class="w-10 h-10 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
          <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
        </svg>
      );
    }
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    const iconColors: Record<string, string> = {
      pdf: 'text-red-500',
      doc: 'text-blue-500', docx: 'text-blue-500',
      xls: 'text-green-500', xlsx: 'text-green-500',
      jpg: 'text-purple-500', jpeg: 'text-purple-500', png: 'text-purple-500', gif: 'text-purple-500',
      mp4: 'text-pink-500', mov: 'text-pink-500', webm: 'text-pink-500',
      mp3: 'text-orange-500', wav: 'text-orange-500',
      zip: 'text-yellow-600', rar: 'text-yellow-600',
    };
    return (
      <svg class={`w-10 h-10 ${iconColors[ext] || 'text-gray-400'}`} fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
      </svg>
    );
  };

  const renderPreview = () => {
    const url = previewUrl();
    const mime = previewMimeType();
    const f = file();
    if (!url || !mime || !f) return null;

    const ext = f.filename.split('.').pop()?.toLowerCase() || '';

    if (mime.startsWith('image/')) {
      return <img src={url} alt={f.filename} class="max-w-full max-h-[70vh] mx-auto rounded-lg shadow-lg" />;
    }
    if (mime.startsWith('video/')) {
      return <video src={url} controls class="max-w-full max-h-[70vh] mx-auto rounded-lg shadow-lg" />;
    }
    if (mime.startsWith('audio/')) {
      return (
        <div class="flex flex-col items-center gap-6 py-8">
          <div class="w-32 h-32 bg-gray-700 rounded-full flex items-center justify-center">
            <svg class="w-16 h-16 text-gray-400" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>
            </svg>
          </div>
          <audio src={url} controls class="w-full max-w-md" />
        </div>
      );
    }
    if (mime === 'application/pdf') {
      return <iframe src={url} class="w-full h-[70vh] rounded-lg bg-white" />;
    }
    if (ext === 'csv') {
      return <CsvPreview url={url} />;
    }
    if (ext === 'xlsx' || ext === 'xls') {
      return <ExcelPreview url={url} />;
    }
    if (ext === 'docx' || ext === 'doc') {
      return <WordPreview url={url} />;
    }
    if (mime.startsWith('text/') || mime === 'application/json') {
      return (
        <iframe src={url} class="w-full h-[70vh] rounded-lg bg-gray-900 text-gray-300" />
      );
    }

    // Non-previewable file
    return (
      <div class="flex flex-col items-center gap-6 py-12">
        {getFileIcon(f.filename, false)}
        <p class="text-gray-400">Preview not available for this file type</p>
      </div>
    );
  };

  // Error pages
  if (error()) {
    return (
      <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div class="bg-gray-800 rounded-xl shadow-2xl max-w-md w-full p-8 text-center">
          <Show when={errorType() === 'unauthorized'}>
            <div class="w-20 h-20 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <svg class="w-10 h-10 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 class="text-2xl font-bold text-white mb-2">Access Denied</h1>
            <p class="text-gray-400 mb-6">You don't have permission to view this file or folder.</p>
          </Show>
          
          <Show when={errorType() === 'notfound'}>
            <div class="w-20 h-20 bg-yellow-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <svg class="w-10 h-10 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h1 class="text-2xl font-bold text-white mb-2">Not Found</h1>
            <p class="text-gray-400 mb-6">This file or folder doesn't exist or has been deleted.</p>
          </Show>
          
          <Show when={errorType() === 'error'}>
            <div class="w-20 h-20 bg-gray-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <svg class="w-10 h-10 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h1 class="text-2xl font-bold text-white mb-2">Something Went Wrong</h1>
            <p class="text-gray-400 mb-6">{error()}</p>
          </Show>
          
          <div class="flex gap-3 justify-center">
            <button
              onClick={goToDrive}
              class="px-6 py-2.5 bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium transition-colors"
            >
              Go to My Drive
            </button>
          </div>
          
          <p class="text-gray-500 text-sm mt-6">
            🔒 SecureVault • End-to-End Encrypted
          </p>
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Loading state */}
      <Show when={isLoading()}>
        <SkeletonFileViewer />
      </Show>

      {/* Not found state - when loading finished but no file and no error */}
      <Show when={!isLoading() && !file() && !error()}>
        <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
          <div class="bg-gray-800 rounded-xl shadow-2xl max-w-md w-full p-8 text-center">
            <div class="w-20 h-20 bg-yellow-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <svg class="w-10 h-10 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h1 class="text-2xl font-bold text-white mb-2">File Not Found</h1>
            <p class="text-gray-400 mb-6">This file or folder doesn't exist, has been deleted, or you don't have access to it.</p>
            
            <div class="flex gap-3 justify-center">
              <button
                onClick={goToDrive}
                class="px-6 py-2.5 bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium transition-colors"
              >
                Go to My Drive
              </button>
            </div>
            
            <p class="text-gray-500 text-sm mt-6">
              🔒 SecureVault • End-to-End Encrypted
            </p>
          </div>
        </div>
      </Show>

      {/* Content when not loading */}
      <Show when={!isLoading() && file()}>
        {/* Folder view */}
        <Show when={file()?.isFolder}>
          <div class="min-h-screen bg-gray-900">
            {/* Header */}
            <header class="bg-gray-800 border-b border-gray-700">
              <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
                <div class="flex items-center gap-4">
                  {/* Back button - shows parent folder or home */}
                  <Show when={hasParentFolder()} fallback={
                    <button
                      onClick={goToDrive}
                      class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors"
                      title="Go to My Drive"
                    >
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                      </svg>
                    </button>
                  }>
                    <button
                      onClick={goBack}
                      class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors"
                      title={`Back to ${parentPath()[parentPath().length - 1]?.name || 'folder'}`}
                    >
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                      </svg>
                    </button>
                  </Show>
                  <div class="flex items-center gap-3">
                    <svg class="w-8 h-8 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                      <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                    </svg>
                    <div>
                      <h1 class="text-lg font-semibold text-white">{file()?.filename}</h1>
                      <p class="text-sm text-gray-400">{folderContents().length} items</p>
                    </div>
                  </div>
                </div>
                <div class="text-sm text-gray-400">
                  Logged in as <span class="text-white">{user()?.displayName || user()?.username}</span>
                </div>
              </div>
            </header>

            {/* Folder Contents */}
            <main class="max-w-6xl mx-auto px-4 py-6">
              <Show when={folderContents().length === 0}>
                <div class="text-center py-16 text-gray-400">
                  <svg class="w-16 h-16 mx-auto mb-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                  </svg>
                  <p>This folder is empty</p>
                </div>
              </Show>
              
              <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
                <For each={folderContents()}>
                  {(item) => (
                    <div
                      onClick={() => openItem(item)}
                      class="bg-gray-800 rounded-xl p-4 cursor-pointer hover:bg-gray-750 hover:ring-2 hover:ring-primary-500/50 transition-all group"
                    >
                      <div class="flex flex-col items-center text-center">
                        {getFileIcon(item.filename, item.isFolder)}
                        <p class="mt-3 text-sm text-white truncate w-full">{item.filename}</p>
                        <p class="text-xs text-gray-500 mt-1">
                          {item.isFolder ? 'Folder' : formatSize(item.fileSize)}
                        </p>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </main>
          </div>
        </Show>

        {/* File view */}
        <Show when={!file()?.isFolder}>
          <div class="min-h-screen bg-gray-900 flex flex-col">
            {/* Header */}
            <header class="bg-gray-800 border-b border-gray-700 flex-shrink-0">
              <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
                <div class="flex items-center gap-4">
                  {/* Back button - shows parent folder or home */}
                  <Show when={hasParentFolder()} fallback={
                    <button
                      onClick={goToDrive}
                      class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors"
                      title="Go to My Drive"
                    >
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                      </svg>
                    </button>
                  }>
                    <button
                      onClick={goBack}
                      class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors"
                      title={`Back to ${parentPath()[parentPath().length - 1]?.name || 'folder'}`}
                    >
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                      </svg>
                    </button>
                  </Show>
                  <div>
                    <h1 class="text-lg font-semibold text-white truncate max-w-md">{file()?.filename}</h1>
                    <div class="flex items-center gap-2 text-sm text-gray-400">
                      <Show when={hasParentFolder()}>
                        <span class="text-gray-500">{parentPath()[parentPath().length - 1]?.name}</span>
                        <span class="text-gray-600">•</span>
                      </Show>
                      <span>{formatSize(file()?.fileSize || 0)} • {formatDate(file()?.createdAt || '')}</span>
                    </div>
                  </div>
                </div>
                <div class="flex items-center gap-3">
                  <button
                    onClick={handleDownload}
                    disabled={isDownloading()}
                    class="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
                  >
                    <Show when={isDownloading()} fallback={
                      <>
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                        Download
                      </>
                    }>
                      <svg class="animate-spin h-4 w-4" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Downloading...
                    </Show>
                  </button>
                </div>
              </div>
            </header>

            {/* Preview Area */}
            <main class="flex-1 flex items-center justify-center p-4 overflow-auto">
              <Show when={previewUrl()} fallback={
                <div class="text-center">
                  <div class="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto mb-4"></div>
                  <p class="text-gray-400">Loading preview...</p>
                </div>
              }>
                {renderPreview()}
              </Show>
            </main>

            {/* Footer */}
            <footer class="bg-gray-800 border-t border-gray-700 py-2 text-center text-gray-500 text-xs flex-shrink-0">
              🔒 SecureVault • End-to-End Encrypted
            </footer>
          </div>
        </Show>
      </Show>
    </>
  );
}
