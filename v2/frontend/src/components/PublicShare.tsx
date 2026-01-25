import { createSignal, createEffect, Show } from 'solid-js';

interface SharedFile {
  id: string;
  filename: string;
  fileSize: number;
  encryptedKey: string;
  iv: string;
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
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );
}

export default function PublicShare() {
  const [file, setFile] = createSignal<SharedFile | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [isLoading, setIsLoading] = createSignal(true);
  const [isDownloading, setIsDownloading] = createSignal(false);
  const [decryptionKey, setDecryptionKey] = createSignal<string | null>(null);
  const [decryptionIv, setDecryptionIv] = createSignal<string | null>(null);
  
  // Preview state
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
      } else {
        setFile(data.file);
        
        // Auto-load preview for previewable files if we have the key
        if (fragment && isPreviewable(data.file.filename)) {
          loadPreview(fragment.key, fragment.iv, data.file.filename);
        }
      }
    } catch (err) {
      setError('Failed to load shared file');
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
  
  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
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
        (previewUrl() || textContent()) ? 'max-w-4xl w-full' : 'max-w-md w-full'
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
              <p class="text-primary-100 text-sm">Shared File</p>
            </div>
          </div>
        </div>
        
        {/* Content */}
        <div class="p-6">
          <Show when={isLoading()}>
            <div class="flex flex-col items-center justify-center py-12">
              <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mb-4"></div>
              <p class="text-gray-400">Loading shared file...</p>
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
          
          <Show when={!isLoading() && !error() && file()}>
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
