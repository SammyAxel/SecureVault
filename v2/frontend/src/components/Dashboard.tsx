import { createSignal, createEffect, For, Show } from 'solid-js';
import { useAuth } from '../stores/auth.jsx';
import * as api from '../lib/api';
import type { FileItem } from '../lib/api';
import ShareModal from './ShareModal';
import {
  getCurrentKeys,
  importEncryptionPrivateKey,
  importEncryptionPublicKey,
  encryptFile,
  decryptFile,
  wrapKey,
  unwrapKey,
  base64ToUint8Array,
  arrayBufferToBase64,
} from '../lib/crypto';

// Helper to get MIME type from filename
function getMimeType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  const mimeTypes: Record<string, string> = {
    // Images
    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 
    'gif': 'image/gif', 'webp': 'image/webp', 'svg': 'image/svg+xml', 'bmp': 'image/bmp',
    // Videos
    'mp4': 'video/mp4', 'webm': 'video/webm', 'ogg': 'video/ogg', 'mov': 'video/quicktime',
    // Audio
    'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'flac': 'audio/flac', 'm4a': 'audio/mp4',
    // Documents
    'pdf': 'application/pdf',
    // Text/Code
    'txt': 'text/plain', 'md': 'text/markdown', 'json': 'application/json',
    'js': 'text/javascript', 'ts': 'text/typescript', 'html': 'text/html', 
    'css': 'text/css', 'py': 'text/x-python', 'java': 'text/x-java',
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

function isPreviewable(filename: string): boolean {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  const previewable = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 
    'mp4', 'webm', 'ogg', 'mov', 'mp3', 'wav', 'flac', 'm4a', 
    'pdf', 'txt', 'md', 'json', 'js', 'ts', 'html', 'css', 'py', 'java'];
  return previewable.includes(ext);
}

export default function Dashboard() {
  const { user, logout, token } = useAuth();
  const [files, setFiles] = createSignal<FileItem[]>([]);
  const [currentFolder, setCurrentFolder] = createSignal<string | null>(null);
  const [folderPath, setFolderPath] = createSignal<Array<{ id: string | null; name: string }>>([{ id: null, name: 'My Files' }]);
  const [isLoading, setIsLoading] = createSignal(false);
  const [isDragging, setIsDragging] = createSignal(false);
  const [uploadProgress, setUploadProgress] = createSignal<string | null>(null);
  
  // Preview state
  const [previewFile, setPreviewFile] = createSignal<{ url: string; filename: string; mimeType: string } | null>(null);
  
  // Share modal state
  const [shareFile, setShareFile] = createSignal<FileItem | null>(null);

  // Load files
  const loadFiles = async () => {
    setIsLoading(true);
    try {
      const result = await api.listFiles(currentFolder() || undefined);
      setFiles(result.files);
    } catch (error) {
      console.error('Failed to load files:', error);
    } finally {
      setIsLoading(false);
    }
  };

  createEffect(() => {
    loadFiles();
  });

  // Navigate to folder
  const navigateToFolder = (folderId: string | null, folderName: string) => {
    if (folderId === null) {
      setFolderPath([{ id: null, name: 'My Files' }]);
    } else {
      setFolderPath([...folderPath(), { id: folderId, name: folderName }]);
    }
    setCurrentFolder(folderId);
  };

  const navigateUp = (index: number) => {
    const newPath = folderPath().slice(0, index + 1);
    setFolderPath(newPath);
    setCurrentFolder(newPath[newPath.length - 1].id);
  };

  // Handle file upload
  const handleUpload = async (fileList: FileList) => {
    const keys = getCurrentKeys();
    if (!keys) {
      alert('Please login again - keys not found');
      return;
    }

    for (const file of Array.from(fileList)) {
      try {
        setUploadProgress(`Encrypting ${file.name}...`);

        // Read file
        const arrayBuffer = await file.arrayBuffer();

        // Encrypt file
        const { encrypted, key, iv } = await encryptFile(arrayBuffer);

        // Wrap key with user's public key
        const publicKey = await importEncryptionPublicKey(keys.encryptionPublicKey);
        const wrappedKey = await wrapKey(key, publicKey);

        setUploadProgress(`Uploading ${file.name}...`);

        // Upload
        await api.uploadFile(
          file,
          encrypted,
          wrappedKey,
          arrayBufferToBase64(iv),
          currentFolder() || undefined
        );

        setUploadProgress(null);
        loadFiles();
      } catch (error: any) {
        console.error('Upload failed:', error);
        alert(`Failed to upload ${file.name}: ${error.message}`);
        setUploadProgress(null);
      }
    }
  };

  // Handle download
  const handleDownload = async (file: FileItem) => {
    const keys = getCurrentKeys();
    if (!keys) {
      alert('Please login again - keys not found');
      return;
    }

    try {
      setUploadProgress(`Downloading ${file.filename}...`);

      // Download encrypted file
      const { data, encryptedKey, iv } = await api.downloadFile(file.id);

      setUploadProgress(`Decrypting ${file.filename}...`);

      // Unwrap key
      const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      const fileKey = await unwrapKey(encryptedKey, privateKey);

      // Decrypt file
      const decrypted = await decryptFile(data, fileKey, base64ToUint8Array(iv));

      // Download
      const mimeType = getMimeType(file.filename);
      const blob = new Blob([decrypted], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setUploadProgress(null);
    } catch (error: any) {
      console.error('Download failed:', error);
      alert(`Failed to download: ${error.message}`);
      setUploadProgress(null);
    }
  };

  // Handle open/preview file
  const handleOpen = async (file: FileItem) => {
    const keys = getCurrentKeys();
    if (!keys) {
      alert('Please login again - keys not found');
      return;
    }

    try {
      setUploadProgress(`Opening ${file.filename}...`);

      // Download encrypted file
      const { data, encryptedKey, iv } = await api.downloadFile(file.id);

      // Unwrap key
      const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      const fileKey = await unwrapKey(encryptedKey, privateKey);

      // Decrypt file
      const decrypted = await decryptFile(data, fileKey, base64ToUint8Array(iv));

      // Create blob URL for preview
      const mimeType = getMimeType(file.filename);
      const blob = new Blob([decrypted], { type: mimeType });
      const url = URL.createObjectURL(blob);

      setPreviewFile({ url, filename: file.filename, mimeType });
      setUploadProgress(null);
    } catch (error: any) {
      console.error('Open failed:', error);
      alert(`Failed to open: ${error.message}`);
      setUploadProgress(null);
    }
  };

  // Close preview
  const closePreview = () => {
    const preview = previewFile();
    if (preview) {
      URL.revokeObjectURL(preview.url);
    }
    setPreviewFile(null);
  };

  // Handle delete
  const handleDelete = async (file: FileItem) => {
    if (!confirm(`Permanently delete "${file.filename}"? This cannot be undone.`)) return;

    try {
      await api.deleteFile(file.id);
      loadFiles();
    } catch (error: any) {
      alert(`Failed to delete: ${error.message}`);
    }
  };

  // Create folder
  const handleCreateFolder = async () => {
    const name = prompt('Enter folder name:');
    if (!name) return;

    try {
      await api.createFolder(name, currentFolder() || undefined);
      loadFiles();
    } catch (error: any) {
      alert(`Failed to create folder: ${error.message}`);
    }
  };

  // Drag and drop
  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer?.files) {
      handleUpload(e.dataTransfer.files);
    }
  };

  // Format file size
  const formatSize = (bytes: number) => {
    if (bytes === 0) return '—';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  // Storage usage
  const storagePercent = () => {
    const u = user();
    if (!u) return 0;
    return Math.round((u.storageUsed / u.storageQuota) * 100);
  };

  return (
    <div class="pb-20">
      {/* Top bar */}
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center gap-4">
          {/* Breadcrumb */}
          <nav class="flex items-center gap-2 text-sm">
            <For each={folderPath()}>
              {(item, index) => (
                <>
                  {index() > 0 && <span class="text-gray-500">/</span>}
                  <button
                    onClick={() => navigateUp(index())}
                    class={`hover:text-primary-400 ${index() === folderPath().length - 1 ? 'text-white font-medium' : 'text-gray-400'}`}
                  >
                    {item.name}
                  </button>
                </>
              )}
            </For>
          </nav>
        </div>

        <div class="flex items-center gap-3">
          <button
            onClick={handleCreateFolder}
            class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm flex items-center gap-2"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
            </svg>
            New Folder
          </button>

          <label class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-sm cursor-pointer flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Upload
            <input
              type="file"
              multiple
              class="hidden"
              onChange={(e) => e.target.files && handleUpload(e.target.files)}
            />
          </label>

          <button
            onClick={() => logout()}
            class="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg text-sm"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Storage indicator */}
      <div class="mb-6 bg-gray-800 rounded-lg p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-sm text-gray-400">Storage Used</span>
          <span class="text-sm text-white">
            {formatSize(user()?.storageUsed || 0)} / {formatSize(user()?.storageQuota || 0)}
          </span>
        </div>
        <div class="w-full bg-gray-700 rounded-full h-2">
          <div
            class="bg-primary-500 h-2 rounded-full transition-all"
            style={{ width: `${storagePercent()}%` }}
          />
        </div>
      </div>

      {/* Upload progress */}
      <Show when={uploadProgress()}>
        <div class="mb-6 bg-primary-500/20 border border-primary-500 rounded-lg p-4 flex items-center gap-3">
          <svg class="animate-spin h-5 w-5 text-primary-500" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
          <span class="text-primary-300">{uploadProgress()}</span>
        </div>
      </Show>

      {/* Drop zone / File list */}
      <div
        class={`drop-zone ${isDragging() ? 'dragover' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <Show when={isLoading()}>
          <div class="flex items-center justify-center py-12">
            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
          </div>
        </Show>

        <Show when={!isLoading() && files().length === 0}>
          <div class="py-12 text-center">
            <svg class="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <p class="text-gray-400 mb-2">Drag and drop files here</p>
            <p class="text-gray-500 text-sm">or click Upload button above</p>
          </div>
        </Show>

        <Show when={!isLoading() && files().length > 0}>
          <div class="overflow-hidden rounded-lg border border-gray-700">
            <table class="w-full">
              <thead class="bg-gray-800">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Name</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Size</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                  <th class="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-700">
                <For each={files()}>
                  {(file) => (
                    <tr class="file-item">
                      <td class="px-4 py-3">
                        <div class="flex items-center gap-3">
                          {file.isFolder ? (
                            <svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                              <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                            </svg>
                          ) : (
                            <svg class="w-5 h-5 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                              <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
                            </svg>
                          )}
                          {file.isFolder ? (
                            <button
                              onClick={() => navigateToFolder(file.id, file.filename)}
                              class="text-white hover:text-primary-400"
                            >
                              {file.filename}
                            </button>
                          ) : (
                            <span class="text-white">{file.filename}</span>
                          )}
                        </div>
                      </td>
                      <td class="px-4 py-3 text-gray-400 text-sm">
                        {formatSize(file.fileSize)}
                      </td>
                      <td class="px-4 py-3 text-gray-400 text-sm">
                        {new Date(file.createdAt).toLocaleDateString()}
                      </td>
                      <td class="px-4 py-3 text-right">
                        <div class="flex items-center justify-end gap-2">
                          {!file.isFolder && isPreviewable(file.filename) && (
                            <button
                              onClick={() => handleOpen(file)}
                              class="p-2 text-gray-400 hover:text-primary-400 rounded-lg hover:bg-gray-700"
                              title="Open/Preview"
                            >
                              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                              </svg>
                            </button>
                          )}
                          {!file.isFolder && (
                            <button
                              onClick={() => setShareFile(file)}
                              class="p-2 text-gray-400 hover:text-green-400 rounded-lg hover:bg-gray-700"
                              title="Share"
                            >
                              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                              </svg>
                            </button>
                          )}
                          {!file.isFolder && (
                            <button
                              onClick={() => handleDownload(file)}
                              class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
                              title="Download"
                            >
                              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                              </svg>
                            </button>
                          )}
                          <button
                            onClick={() => handleDelete(file)}
                            class="p-2 text-gray-400 hover:text-red-400 rounded-lg hover:bg-gray-700"
                            title="Delete"
                          >
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </div>

      {/* Preview Modal */}
      <Show when={previewFile()}>
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={closePreview}>
          <div class="bg-gray-800 rounded-xl max-w-5xl max-h-[90vh] w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
            {/* Modal Header */}
            <div class="flex items-center justify-between px-4 py-3 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white truncate">{previewFile()?.filename}</h3>
              <button
                onClick={closePreview}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            {/* Modal Content */}
            <div class="p-4 overflow-auto max-h-[calc(90vh-60px)]">
              {/* Image Preview */}
              <Show when={previewFile()?.mimeType.startsWith('image/')}>
                <img 
                  src={previewFile()?.url} 
                  alt={previewFile()?.filename}
                  class="max-w-full max-h-[70vh] mx-auto rounded-lg"
                />
              </Show>
              
              {/* Video Preview */}
              <Show when={previewFile()?.mimeType.startsWith('video/')}>
                <video 
                  src={previewFile()?.url} 
                  controls 
                  class="max-w-full max-h-[70vh] mx-auto rounded-lg"
                />
              </Show>
              
              {/* Audio Preview */}
              <Show when={previewFile()?.mimeType.startsWith('audio/')}>
                <div class="flex flex-col items-center gap-4 py-8">
                  <svg class="w-24 h-24 text-gray-500" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>
                  </svg>
                  <audio src={previewFile()?.url} controls class="w-full max-w-md" />
                </div>
              </Show>
              
              {/* PDF Preview */}
              <Show when={previewFile()?.mimeType === 'application/pdf'}>
                <iframe 
                  src={previewFile()?.url} 
                  class="w-full h-[70vh] rounded-lg bg-white"
                />
              </Show>
              
              {/* Text/Code Preview */}
              <Show when={previewFile()?.mimeType.startsWith('text/') || previewFile()?.mimeType === 'application/json'}>
                <TextPreview url={previewFile()!.url} />
              </Show>
            </div>
          </div>
        </div>
      </Show>

      {/* Share Modal */}
      <Show when={shareFile()}>
        <ShareModal 
          file={shareFile()!} 
          onClose={() => setShareFile(null)} 
        />
      </Show>
    </div>
  );
}

// Text preview component
function TextPreview(props: { url: string }) {
  const [content, setContent] = createSignal<string>('Loading...');
  
  createEffect(async () => {
    try {
      const response = await fetch(props.url);
      const text = await response.text();
      setContent(text);
    } catch {
      setContent('Failed to load text content');
    }
  });
  
  return (
    <pre class="bg-gray-900 p-4 rounded-lg overflow-auto max-h-[70vh] text-sm text-gray-300 font-mono whitespace-pre-wrap">
      {content()}
    </pre>
  );
}
