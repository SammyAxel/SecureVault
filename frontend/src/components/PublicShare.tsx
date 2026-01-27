import { createSignal, createEffect, Show, For } from 'solid-js';

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

// Crypto utilities (inline to avoid circular dependencies)
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function importFileKey(rawKeyBase64: string): Promise<CryptoKey> {
  const keyData = base64ToArrayBuffer(rawKeyBase64);
  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

async function decryptFile(encrypted: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    encrypted
  );
}

export default function PublicShare() {
  // Single file state
  const [file, setFile] = createSignal<SharedFile | null>(null);
  // Folder state
  const [folder, setFolder] = createSignal<SharedFolder | null>(null);
  const [isFolder, setIsFolder] = createSignal(false);
  const [expandedFolders, setExpandedFolders] = createSignal<Set<string>>(new Set());
  
  const [error, setError] = createSignal<string | null>(null);
  const [isLoading, setIsLoading] = createSignal(true);
  const [isDownloading, setIsDownloading] = createSignal(false);
  const [downloadingFileId, setDownloadingFileId] = createSignal<string | null>(null);
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
    if (hash) {
      const parts = hash.split(':');
      if (parts.length === 2) {
        return { key: parts[0], iv: parts[1] };
      }
    }
    return null;
  };
  
  const token = getToken();
  
  const getMimeType = (filename: string): string => {
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    const mimeTypes: Record<string, string> = {
      'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
      'gif': 'image/gif', 'webp': 'image/webp', 'svg': 'image/svg+xml', 'bmp': 'image/bmp',
      'mp4': 'video/mp4', 'webm': 'video/webm', 'mov': 'video/quicktime', 'ogg': 'video/ogg',
      'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'flac': 'audio/flac', 'm4a': 'audio/mp4',
      'pdf': 'application/pdf', 'txt': 'text/plain', 'json': 'application/json',
      'js': 'text/javascript', 'ts': 'text/typescript', 'html': 'text/html',
      'css': 'text/css', 'md': 'text/markdown', 'py': 'text/x-python',
      'zip': 'application/zip', 'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    };
    return mimeTypes[ext] || 'application/octet-stream';
  };
  
  const isPreviewable = (filename: string): boolean => {
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    const previewable = [
      'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp',
      'mp4', 'webm', 'ogg', 'mov',
      'mp3', 'wav', 'flac', 'm4a',
      'pdf', 'txt', 'md', 'json', 'js', 'ts', 'html', 'css', 'py'
    ];
    return previewable.includes(ext);
  };
  
  createEffect(async () => {
    // Parse the fragment for decryption key
    const fragment = parseFragment();
    if (fragment) {
      setDecryptionKey(fragment.key);
      setDecryptionIv(fragment.iv);
    }
    
    if (!token) {
      setError('Invalid share link');
      setIsLoading(false);
      return;
    }
    
    try {
      const response = await fetch(`/api/public/${token}`);
      const data = await response.json();
      
      if (!response.ok) {
        setError(data.msg || 'Link not found or expired');
      } else if (data.isFolder) {
        // It's a folder share
        setIsFolder(true);
        setFolder(data.folder);
      } else {
        // It's a single file share
        setIsFolder(false);
        setFile(data.file);
        
        // Auto-load preview for previewable files if we have the key
        if (fragment && isPreviewable(data.file.filename)) {
          loadPreview(fragment.key, fragment.iv, data.file.filename);
        }
      }
    } catch (err) {
      setError('Failed to load shared content');
    } finally {
      setIsLoading(false);
    }
  });
  
  const loadPreview = async (key: string, iv: string, filename: string) => {
    if (!token) return;
    
    setIsLoadingPreview(true);
    
    try {
      const response = await fetch(`/api/public/${token}/download`);
      
      if (!response.ok) {
        throw new Error('Failed to load preview');
      }
      
      const encryptedData = await response.arrayBuffer();
      const cryptoKey = await importFileKey(key);
      const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
      const decryptedData = await decryptFile(encryptedData, cryptoKey, ivBytes);
      
      const mimeType = getMimeType(filename);
      setPreviewMimeType(mimeType);
      
      // For text files, read as text
      if (mimeType.startsWith('text/') || mimeType === 'application/json') {
        const text = new TextDecoder().decode(decryptedData);
        setTextContent(text);
      } else {
        // For binary files, create blob URL
        const blob = new Blob([decryptedData], { type: mimeType });
        const url = URL.createObjectURL(blob);
        setPreviewUrl(url);
      }
    } catch (err) {
      console.error('Preview error:', err);
      // Don't show error, just don't show preview
    } finally {
      setIsLoadingPreview(false);
    }
  };
  
  const handleDownload = async () => {
    if (!token || !file()) return;
    
    setIsDownloading(true);
    
    try {
      // If we already have the preview URL, use it
      if (previewUrl()) {
        const a = document.createElement('a');
        a.href = previewUrl()!;
        a.download = file()!.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setIsDownloading(false);
        return;
      }
      
      // If we have text content, create blob from it
      if (textContent()) {
        const blob = new Blob([textContent()!], { type: previewMimeType() || 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file()!.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setIsDownloading(false);
        return;
      }
      
      const response = await fetch(`/api/public/${token}/download`);
      
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.msg || 'Download failed');
      }
      
      let blob: Blob;
      const key = decryptionKey();
      const iv = decryptionIv();
      
      if (key && iv) {
        const encryptedData = await response.arrayBuffer();
        const cryptoKey = await importFileKey(key);
        const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
        const decryptedData = await decryptFile(encryptedData, cryptoKey, ivBytes);
        
        const mimeType = getMimeType(file()!.filename);
        blob = new Blob([decryptedData], { type: mimeType });
      } else {
        blob = await response.blob();
      }
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file()!.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Download error:', err);
      setError(err.message || 'Download failed - the link may be incomplete');
    } finally {
      setIsDownloading(false);
    }
  };

  // Download a file from a shared folder
  const handleFolderFileDownload = async (item: FolderItem) => {
    if (!token || item.isFolder) return;
    
    setDownloadingFileId(item.id);
    
    try {
      const response = await fetch(`/api/public/${token}/file/${item.id}/download`);
      
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.msg || 'Download failed');
      }
      
      const blob = await response.blob();
      
      // Note: For folder shares, files are downloaded as-is (encrypted)
      // In a real implementation, you would need to handle decryption
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = item.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Download error:', err);
      setError(err.message || 'Download failed');
    } finally {
      setDownloadingFileId(null);
    }
  };
  
  const formatSize = (bytes: number | undefined) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const toggleFolder = (folderId: string) => {
    const expanded = new Set(expandedFolders());
    if (expanded.has(folderId)) {
      expanded.delete(folderId);
    } else {
      expanded.add(folderId);
    }
    setExpandedFolders(expanded);
  };

  // Count total files in folder recursively
  const countFiles = (items: FolderItem[]): number => {
    let count = 0;
    for (const item of items) {
      if (item.isFolder && item.children) {
        count += countFiles(item.children);
      } else if (!item.isFolder) {
        count++;
      }
    }
    return count;
  };

  // Recursive component to render folder items
  const FolderItemRow = (props: { item: FolderItem; depth: number }) => {
    const isExpanded = () => expandedFolders().has(props.item.id);
    
    return (
      <>
        <div 
          class={`flex items-center gap-3 py-2 px-3 hover:bg-gray-700/50 rounded-lg ${
            props.item.isFolder ? 'cursor-pointer' : ''
          }`}
          style={{ "padding-left": `${props.depth * 20 + 12}px` }}
          onClick={() => props.item.isFolder && toggleFolder(props.item.id)}
        >
          {/* Icon */}
          {props.item.isFolder ? (
            <div class="flex items-center">
              <svg 
                class={`w-4 h-4 text-gray-400 mr-1 transition-transform ${isExpanded() ? 'rotate-90' : ''}`} 
                fill="currentColor" 
                viewBox="0 0 20 20"
              >
                <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" />
              </svg>
              <svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
              </svg>
            </div>
          ) : (
            <svg class="w-5 h-5 text-gray-400 ml-5" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
            </svg>
          )}
          
          {/* Filename */}
          <span class="flex-1 text-white text-sm truncate">{props.item.filename}</span>
          
          {/* Size / Download */}
          {!props.item.isFolder && (
            <>
              <span class="text-gray-400 text-xs">{formatSize(props.item.fileSize)}</span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleFolderFileDownload(props.item);
                }}
                disabled={downloadingFileId() === props.item.id}
                class="p-1.5 text-gray-400 hover:text-white hover:bg-gray-600 rounded-lg transition-colors disabled:opacity-50"
                title="Download"
              >
                {downloadingFileId() === props.item.id ? (
                  <svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                ) : (
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                )}
              </button>
            </>
          )}
        </div>
        
        {/* Children */}
        <Show when={props.item.isFolder && isExpanded() && props.item.children}>
          <For each={props.item.children}>
            {(child) => <FolderItemRow item={child} depth={props.depth + 1} />}
          </For>
        </Show>
      </>
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
    
    if (mime.startsWith('text/') || mime === 'application/json') {
      return (
        <pre class="bg-gray-900 p-4 rounded-lg overflow-auto max-h-[60vh] text-sm text-gray-300 font-mono whitespace-pre-wrap text-left">
          {text}
        </pre>
      );
    }
    
    return null;
  };
  
  return (
    <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div class={`bg-gray-800 rounded-xl shadow-2xl overflow-hidden transition-all ${
        isFolder() ? 'max-w-2xl w-full' : (previewUrl() || textContent()) ? 'max-w-4xl w-full' : 'max-w-md w-full'
      }`}>
        {/* Header */}
        <div class="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center">
              <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h1 class="text-lg font-bold text-white">SecureVault</h1>
              <p class="text-primary-100 text-sm">
                {isFolder() ? 'Shared Folder' : 'Shared File'}
              </p>
            </div>
          </div>
        </div>
        
        {/* Content */}
        <div class="p-6">
          <Show when={isLoading()}>
            <div class="flex flex-col items-center justify-center py-12">
              <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mb-4"></div>
              <p class="text-gray-400">Loading shared content...</p>
            </div>
          </Show>
          
          <Show when={error()}>
            <div class="flex flex-col items-center justify-center py-12 text-center">
              <div class="w-16 h-16 bg-red-500/20 rounded-full flex items-center justify-center mb-4">
                <svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h2 class="text-xl font-semibold text-white mb-2">Link Unavailable</h2>
              <p class="text-gray-400">{error()}</p>
              <a
                href="/"
                class="mt-6 px-6 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm"
              >
                Go to SecureVault
              </a>
            </div>
          </Show>
          
          {/* Single File View */}
          <Show when={!isLoading() && !error() && !isFolder() && file()}>
            <div class="text-center">
              {/* Preview Section */}
              <Show when={isLoadingPreview()}>
                <div class="flex flex-col items-center justify-center py-8 mb-6">
                  <div class="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mb-3"></div>
                  <p class="text-gray-400 text-sm">Loading preview...</p>
                </div>
              </Show>
              
              <Show when={!isLoadingPreview() && (previewUrl() || textContent())}>
                <div class="mb-6">
                  {renderPreview()}
                </div>
              </Show>
              
              {/* File Info */}
              <h2 class="text-xl font-semibold text-white mb-1 break-all">
                {file()!.filename}
              </h2>
              
              <p class="text-gray-400 text-sm mb-6">
                {formatSize(file()!.fileSize)}
              </p>
              
              {/* Download Button */}
              <button
                onClick={handleDownload}
                disabled={isDownloading()}
                class="w-full max-w-xs mx-auto py-3 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 rounded-lg text-white font-medium flex items-center justify-center gap-2 transition-colors"
              >
                {isDownloading() ? (
                  <>
                    <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Downloading...
                  </>
                ) : (
                  <>
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                    Download File
                  </>
                )}
              </button>
              
              {/* Security Note */}
              <p class="text-gray-500 text-xs mt-4">
                {decryptionKey() 
                  ? '🔓 File decrypted securely in your browser.'
                  : '⚠️ Incomplete link - file may download encrypted.'}
              </p>
            </div>
          </Show>

          {/* Folder View */}
          <Show when={!isLoading() && !error() && isFolder() && folder()}>
            <div>
              {/* Folder Header */}
              <div class="flex items-center gap-3 mb-4 pb-4 border-b border-gray-700">
                <svg class="w-10 h-10 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                </svg>
                <div>
                  <h2 class="text-xl font-semibold text-white">{folder()!.filename}</h2>
                  <p class="text-gray-400 text-sm">
                    {countFiles(folder()!.children)} file(s)
                  </p>
                </div>
              </div>
              
              {/* Folder Contents */}
              <div class="max-h-[400px] overflow-y-auto">
                <Show when={folder()!.children.length === 0}>
                  <p class="text-gray-400 text-center py-8">This folder is empty</p>
                </Show>
                <For each={folder()!.children}>
                  {(item) => <FolderItemRow item={item} depth={0} />}
                </For>
              </div>
              
              {/* Note for folder shares */}
              <p class="text-gray-500 text-xs mt-4 text-center">
                ℹ️ Click on folders to expand. Click download icon to download individual files.
              </p>
            </div>
          </Show>
        </div>
        
        {/* Footer */}
        <div class="bg-gray-900 px-6 py-3 text-center">
          <p class="text-gray-500 text-xs">
            🔒 Secured by SecureVault • End-to-End Encrypted
          </p>
        </div>
      </div>
    </div>
  );
}
