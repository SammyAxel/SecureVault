import { createSignal, Show } from 'solid-js';
import * as api from '../lib/api';
import type { FileItem } from '../lib/api';
import {
  getCurrentKeys,
  importEncryptionPrivateKey,
  unwrapKey,
  arrayBufferToBase64,
} from '../lib/crypto';

interface ShareModalProps {
  file: FileItem;
  onClose: () => void;
}

type ShareType = 'permanent' | 'days' | 'views';

export default function ShareModal(props: ShareModalProps) {
  const [shareType, setShareType] = createSignal<ShareType>('permanent');
  const [days, setDays] = createSignal(7);
  const [maxViews, setMaxViews] = createSignal(10);
  const [isLoading, setIsLoading] = createSignal(false);
  const [shareLink, setShareLink] = createSignal<string | null>(null);
  const [error, setError] = createSignal('');
  const [copied, setCopied] = createSignal(false);

  const createShare = async () => {
    setError('');
    setIsLoading(true);
    
    try {
      let expiresInHours: number;
      let maxAccess: number | undefined;
      
      switch (shareType()) {
        case 'permanent':
          // 10 years = effectively permanent
          expiresInHours = 24 * 365 * 10;
          maxAccess = undefined;
          break;
        case 'days':
          expiresInHours = 24 * days();
          maxAccess = undefined;
          break;
        case 'views':
          // Default to 30 days expiry for view-limited shares
          expiresInHours = 24 * 30;
          maxAccess = maxViews();
          break;
      }
      
      const result = await api.createPublicShare(
        props.file.id,
        expiresInHours,
        maxAccess
      );
      
      const baseUrl = window.location.origin;
      
      if (props.file.isFolder) {
        // For folders, we don't include encryption keys in the URL
        // Each file in the folder has its own key that will be included when downloading
        setShareLink(`${baseUrl}/share/${result.token}`);
      } else {
        // For files, include the decryption key in the URL fragment
        const keys = getCurrentKeys();
        if (!keys) {
          throw new Error('Please login again - keys not found');
        }
        
        // Decrypt the file key using owner's private key
        const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
        const fileKey = await unwrapKey(props.file.encryptedKey, privateKey);
        
        // Export the raw key for the share URL
        const rawKey = await crypto.subtle.exportKey('raw', fileKey);
        const keyBase64 = arrayBufferToBase64(rawKey);
        
        // Build full URL with key in fragment (fragment is not sent to server)
        // Format: /share/{token}#{key}:{iv}
        setShareLink(`${baseUrl}/share/${result.token}#${keyBase64}:${props.file.iv}`);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to create share link');
    } finally {
      setIsLoading(false);
    }
  };

  const copyLink = async () => {
    if (shareLink()) {
      await navigator.clipboard.writeText(shareLink()!);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={props.onClose}>
      <div class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
          <h3 class="text-lg font-medium text-white">
            Share {props.file.isFolder ? 'Folder' : 'File'}
          </h3>
          <button
            onClick={props.onClose}
            class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        {/* Content */}
        <div class="p-6">
          {/* File/Folder info */}
          <div class="flex items-center gap-3 mb-6 p-3 bg-gray-700/50 rounded-lg">
            {props.file.isFolder ? (
              <svg class="w-8 h-8 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
              </svg>
            ) : (
              <svg class="w-8 h-8 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
              </svg>
            )}
            <div class="flex-1 min-w-0">
              <span class="text-white truncate block">{props.file.filename}</span>
              {props.file.isFolder && (
                <span class="text-gray-400 text-sm">All files in this folder will be shared</span>
              )}
            </div>
          </div>
          
          {error() && (
            <div class="bg-red-500/20 border border-red-500 text-red-300 rounded-lg p-3 mb-4">
              {error()}
            </div>
          )}
          
          <Show when={!shareLink()} fallback={
            /* Share link generated */
            <div>
              <label class="block text-gray-400 text-sm mb-2">Share Link</label>
              <div class="flex gap-2">
                <input
                  type="text"
                  value={shareLink() || ''}
                  readOnly
                  class="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none"
                />
                <button
                  onClick={copyLink}
                  class={`px-4 py-3 rounded-lg font-medium transition-colors ${
                    copied() 
                      ? 'bg-green-600 text-white' 
                      : 'bg-primary-600 hover:bg-primary-700 text-white'
                  }`}
                >
                  {copied() ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <p class="text-gray-500 text-sm mt-3">
                {shareType() === 'permanent' && 'This link will never expire.'}
                {shareType() === 'days' && `This link will expire in ${days()} day${days() > 1 ? 's' : ''}.`}
                {shareType() === 'views' && `This link will expire after ${maxViews()} view${maxViews() > 1 ? 's' : ''}.`}
              </p>
              
              <button
                onClick={() => setShareLink(null)}
                class="mt-4 w-full py-3 bg-gray-700 hover:bg-gray-600 rounded-lg text-white font-medium"
              >
                Create Another Link
              </button>
            </div>
          }>
            {/* Share type selection */}
            <div class="space-y-3 mb-6">
              <label class="block text-gray-400 text-sm mb-2">Link Type</label>
              
              {/* Permanent */}
              <label class={`flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                shareType() === 'permanent' 
                  ? 'border-primary-500 bg-primary-500/10' 
                  : 'border-gray-600 bg-gray-700/50 hover:border-gray-500'
              }`}>
                <input
                  type="radio"
                  name="shareType"
                  checked={shareType() === 'permanent'}
                  onChange={() => setShareType('permanent')}
                  class="w-4 h-4 text-primary-500"
                />
                <div>
                  <div class="text-white font-medium">Permanent Link</div>
                  <div class="text-gray-400 text-sm">Never expires</div>
                </div>
              </label>
              
              {/* Expires by days */}
              <label class={`flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                shareType() === 'days' 
                  ? 'border-primary-500 bg-primary-500/10' 
                  : 'border-gray-600 bg-gray-700/50 hover:border-gray-500'
              }`}>
                <input
                  type="radio"
                  name="shareType"
                  checked={shareType() === 'days'}
                  onChange={() => setShareType('days')}
                  class="w-4 h-4 text-primary-500"
                />
                <div class="flex-1">
                  <div class="text-white font-medium">Expires After Time</div>
                  <div class="text-gray-400 text-sm">Self-destructs after set days</div>
                </div>
              </label>
              
              <Show when={shareType() === 'days'}>
                <div class="ml-7 mt-2">
                  <div class="flex items-center gap-3">
                    <input
                      type="number"
                      min="1"
                      max="365"
                      value={days()}
                      onInput={(e) => setDays(parseInt(e.currentTarget.value) || 1)}
                      class="w-24 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-primary-500"
                    />
                    <span class="text-gray-400">days</span>
                  </div>
                </div>
              </Show>
              
              {/* Expires by views */}
              <label class={`flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                shareType() === 'views' 
                  ? 'border-primary-500 bg-primary-500/10' 
                  : 'border-gray-600 bg-gray-700/50 hover:border-gray-500'
              }`}>
                <input
                  type="radio"
                  name="shareType"
                  checked={shareType() === 'views'}
                  onChange={() => setShareType('views')}
                  class="w-4 h-4 text-primary-500"
                />
                <div class="flex-1">
                  <div class="text-white font-medium">Limited Views</div>
                  <div class="text-gray-400 text-sm">Self-destructs after N views</div>
                </div>
              </label>
              
              <Show when={shareType() === 'views'}>
                <div class="ml-7 mt-2">
                  <div class="flex items-center gap-3">
                    <input
                      type="number"
                      min="1"
                      max="1000"
                      value={maxViews()}
                      onInput={(e) => setMaxViews(parseInt(e.currentTarget.value) || 1)}
                      class="w-24 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-primary-500"
                    />
                    <span class="text-gray-400">views</span>
                  </div>
                </div>
              </Show>
            </div>
            
            <button
              onClick={createShare}
              disabled={isLoading()}
              class="w-full py-3 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 rounded-lg text-white font-medium flex items-center justify-center gap-2"
            >
              {isLoading() ? (
                <>
                  <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Creating...
                </>
              ) : (
                <>
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                  </svg>
                  Create Share Link
                </>
              )}
            </button>
          </Show>
        </div>
      </div>
    </div>
  );
}
