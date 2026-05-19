import { createSignal, Show } from 'solid-js';
import * as api from '../lib/api';
import type { FileItem } from '../lib/api';
import {
  getCurrentKeys,
  importEncryptionPrivateKey,
  importEncryptionPublicKey,
  unwrapKey,
  wrapKey,
  derivePublicShareKeyPBKDF2,
  generatePublicShareSaltB64,
  wrapFileKeyForPublicShare,
} from '../lib/crypto';
import { awaitMinElapsed, MIN_FORM_SUBMIT_MS } from '../lib/motion';

interface ShareModalProps {
  file: FileItem;
  onClose: () => void;
}

type ShareType = 'permanent' | 'days' | 'views';
type ModalTab = 'public' | 'user';

export default function ShareModal(props: ShareModalProps) {
  const [modalTab, setModalTab] = createSignal<ModalTab>('public');

  // Public link state
  const [shareType, setShareType] = createSignal<ShareType>('permanent');
  const [days, setDays] = createSignal(7);
  const [maxViews, setMaxViews] = createSignal(10);
  const [isLoading, setIsLoading] = createSignal(false);
  const [shareLink, setShareLink] = createSignal<string | null>(null);
  const [error, setError] = createSignal('');
  const [copied, setCopied] = createSignal(false);
  const [passphrase, setPassphrase] = createSignal('');
  const [passphraseConfirm, setPassphraseConfirm] = createSignal('');

  // User share state
  const [userShareUsername, setUserShareUsername] = createSignal('');
  const [userShareLoading, setUserShareLoading] = createSignal(false);
  const [userShareError, setUserShareError] = createSignal('');
  const [userShareSuccess, setUserShareSuccess] = createSignal<string | null>(null);

  // ============ CREATE PUBLIC LINK ============
  const createShare = async () => {
    const opStart = Date.now();
    setError('');
    setIsLoading(true);
    
    try {
      const pw = passphrase();
      if (pw.trim().length < 8) {
        throw new Error('Passphrase must be at least 8 characters');
      }
      if (pw !== passphraseConfirm()) {
        throw new Error('Passphrase confirmation does not match');
      }

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
      
      const kdfAlg = 'pbkdf2-sha256';
      const kdfParams = { iterations: 310000, hash: 'SHA-256' as const };
      const kdfSalt = generatePublicShareSaltB64(16);
      const shareKey = await derivePublicShareKeyPBKDF2(pw, kdfSalt, kdfParams);
      
      const baseUrl = window.location.origin;
      
      if (props.file.isFolder) {
        // Folder shares: compute per-item wrapped keys and store them server-side (not in URL).
        const keys = getCurrentKeys();
        if (!keys) {
          throw new Error('Please login again - keys not found');
        }

        const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);

        // Fetch full folder tree via authenticated listing (avoids relying on public token to discover keys).
        const listAllDescendants = async (parentId: string): Promise<FileItem[]> => {
          const res = await api.listFiles(parentId);
          const direct = res.files;
          const out: FileItem[] = [...direct];
          for (const it of direct) {
            if (it.isFolder) {
              const more = await listAllDescendants(it.id);
              out.push(...more);
            }
          }
          return out;
        };

        const all = await listAllDescendants(props.file.id);
        // Include the root folder itself so its name can be decrypted publicly.
        const root: FileItem = props.file;
        const allWithRoot = [root, ...all];

        const wrappedItems: Array<{ fileId: string; wrappedKey: string; wrappedKeyIv: string }> = [];
        for (const it of allWithRoot) {
          try {
            const fk = await unwrapKey(it.encryptedKey, privateKey);
            const wrapped = await wrapFileKeyForPublicShare(fk, shareKey);
            wrappedItems.push({ fileId: it.id, wrappedKey: wrapped.wrappedKey, wrappedKeyIv: wrapped.wrappedKeyIv });
          } catch {
            // Ignore: item name/content will remain encrypted for public viewers.
          }
        }

        const result = await api.createPublicShare(props.file.id, expiresInHours, maxAccess, {
          kdfAlg,
          kdfParams,
          kdfSalt,
          items: wrappedItems,
        });

        setShareLink(`${baseUrl}/share/${result.token}`);
      } else {
        const keys = getCurrentKeys();
        if (!keys) {
          throw new Error('Please login again - keys not found');
        }
        
        // Decrypt the file key using owner's private key
        const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
        const fileKey = await unwrapKey(props.file.encryptedKey, privateKey);
        const wrapped = await wrapFileKeyForPublicShare(fileKey, shareKey);

        const result = await api.createPublicShare(props.file.id, expiresInHours, maxAccess, {
          kdfAlg,
          kdfParams,
          kdfSalt,
          wrappedKey: wrapped.wrappedKey,
          wrappedKeyIv: wrapped.wrappedKeyIv,
        });

        setShareLink(`${baseUrl}/share/${result.token}`);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to create share link');
    } finally {
      await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
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

  // ============ SHARE WITH USER ============
  const shareWithUser = async () => {
    const username = userShareUsername().trim();
    setUserShareError('');
    setUserShareSuccess(null);

    if (!username) {
      setUserShareError('Please enter a username');
      return;
    }

    setUserShareLoading(true);
    try {
      const keys = getCurrentKeys();
      if (!keys) throw new Error('Please login again — keys not found');

      // Look up recipient's RSA-OAEP public key
      const recipientInfo = await api.getUserPublicKey(username);
      if (!recipientInfo.encryptionPublicKey) {
        throw new Error('This user cannot receive shared files (no encryption key)');
      }

      const myPrivKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      const recipientPubKey = await importEncryptionPublicKey(recipientInfo.encryptionPublicKey);

      if (props.file.isFolder) {
        // For folders: share the folder + all descendants
        const listAllDescendants = async (parentId: string): Promise<FileItem[]> => {
          const res = await api.listFiles(parentId);
          const out: FileItem[] = [...res.files];
          for (const it of res.files) {
            if (it.isFolder) out.push(...await listAllDescendants(it.id));
          }
          return out;
        };

        const descendants = await listAllDescendants(props.file.id);
        const allItems = [props.file, ...descendants];
        let successCount = 0;

        for (const item of allItems) {
          try {
            const fileKey = await unwrapKey(item.encryptedKey, myPrivKey);
            const encryptedKeyForRecipient = await wrapKey(fileKey, recipientPubKey);
            await api.createUserShare(item.id, username, encryptedKeyForRecipient);
            successCount++;
          } catch { /* skip items that fail individually */ }
        }

        if (successCount === 0) throw new Error('Failed to share any items in this folder');
        setUserShareSuccess(`Shared "${props.file.filename}" (${successCount} items) with @${username}`);
      } else {
        // Single file share
        const fileKey = await unwrapKey(props.file.encryptedKey, myPrivKey);
        const encryptedKeyForRecipient = await wrapKey(fileKey, recipientPubKey);
        await api.createUserShare(props.file.id, username, encryptedKeyForRecipient);
        setUserShareSuccess(`Shared "${props.file.filename}" with @${username}`);
      }

      setUserShareUsername('');
    } catch (err: any) {
      setUserShareError(err.message || 'Failed to share');
    } finally {
      setUserShareLoading(false);
    }
  };

  return (
    <div
      class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 sv-modal-overlay"
      onClick={props.onClose}
      role="presentation"
    >
      <div
        class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden sv-modal-panel"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="share-modal-title"
      >
        {/* Header */}
        <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
          <h3 id="share-modal-title" class="text-lg font-medium text-white">
            Share {props.file.isFolder ? 'Folder' : 'File'}
          </h3>
          <button
            type="button"
            onClick={props.onClose}
            class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
            aria-label="Close"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        {/* Content */}
        <div class="p-6">
          {/* File/Folder info */}
          <div class="flex items-center gap-3 mb-5 p-3 bg-gray-700/50 rounded-lg">
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

          {/* Tab switcher */}
          <div class="flex gap-1 p-1 bg-gray-700/60 rounded-lg mb-5">
            <button
              type="button"
              onClick={() => { setModalTab('public'); setError(''); }}
              class={`flex-1 py-1.5 px-3 rounded-md text-sm font-medium transition-all cursor-pointer ${
                modalTab() === 'public'
                  ? 'bg-gray-600 text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Public Link
            </button>
            <button
              type="button"
              onClick={() => { setModalTab('user'); setUserShareError(''); setUserShareSuccess(null); }}
              class={`flex-1 py-1.5 px-3 rounded-md text-sm font-medium transition-all cursor-pointer ${
                modalTab() === 'user'
                  ? 'bg-gray-600 text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Share with User
            </button>
          </div>

          {/* ============ USER SHARE TAB ============ */}
          <Show when={modalTab() === 'user'}>
            <div class="space-y-4">
              <Show when={userShareSuccess()}>
                <div class="flex items-center gap-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-lg p-3 text-sm">
                  <svg class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {userShareSuccess()}
                </div>
              </Show>

              <Show when={userShareError()}>
                <div class="bg-red-500/20 border border-red-500/50 text-red-300 rounded-lg p-3 text-sm">
                  {userShareError()}
                </div>
              </Show>

              <div>
                <label class="block text-gray-400 text-sm mb-2">Recipient username</label>
                <div class="flex gap-2">
                  <div class="flex-1 relative">
                    <span class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm">@</span>
                    <input
                      type="text"
                      value={userShareUsername()}
                      onInput={(e) => setUserShareUsername(e.currentTarget.value)}
                      onKeyDown={(e) => e.key === 'Enter' && !userShareLoading() && shareWithUser()}
                      placeholder="username"
                      autocomplete="off"
                      class="w-full bg-gray-700 border border-gray-600 rounded-lg pl-7 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-primary-500 transition-colors"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={shareWithUser}
                    disabled={userShareLoading() || !userShareUsername().trim()}
                    class="px-4 py-3 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg text-white font-medium flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <Show
                      when={userShareLoading()}
                      fallback={
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                        </svg>
                      }
                    >
                      <div class="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                    </Show>
                    Share
                  </button>
                </div>
              </div>

              <p class="text-xs text-gray-500">
                The file key is encrypted end-to-end with the recipient's public key — the server never sees the plaintext key.
              </p>
            </div>
          </Show>

          {/* ============ PUBLIC LINK MODE ============ */}
          <Show when={modalTab() === 'public'}>

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
                {shareType() === 'permanent' &&
                  'This link is set to stay valid for up to 10 years (revoke it anytime in your vault).'}
                {shareType() === 'days' && `This link will expire in ${days()} day${days() > 1 ? 's' : ''}.`}
                {shareType() === 'views' &&
                  `This link expires after ${maxViews()} view${maxViews() > 1 ? 's' : ''}, or after 30 days, whichever comes first.`}
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
                  <div class="text-white font-medium">Long-term link</div>
                  <div class="text-gray-400 text-sm">Up to 10 years (you can revoke early)</div>
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

            {/* Passphrase */}
            <div class="space-y-3 mb-6">
              <label class="block text-gray-400 text-sm mb-2">Passphrase</label>
              <input
                type="password"
                value={passphrase()}
                onInput={(e) => setPassphrase(e.currentTarget.value)}
                class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
                placeholder="Enter a passphrase (min 8 chars)"
                autocomplete="new-password"
              />
              <input
                type="password"
                value={passphraseConfirm()}
                onInput={(e) => setPassphraseConfirm(e.currentTarget.value)}
                class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
                placeholder="Confirm passphrase"
                autocomplete="new-password"
              />
              <p class="text-gray-500 text-xs">
                Anyone with the link and passphrase can decrypt this share. The passphrase is never sent to the server.
              </p>
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
          </Show>{/* end modalTab === 'public' */}
        </div>
      </div>
    </div>
  );
}
