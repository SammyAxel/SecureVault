import { createSignal, Show, createEffect, onCleanup } from 'solid-js';
import QRCode from 'qrcode';
import * as api from '../lib/api';
import { toast } from '../stores/toast';
import { getCurrentKeys, encryptKeyBundleForTransfer } from '../lib/crypto';

interface DeviceLinkModalProps {
  open: boolean;
  onClose: () => void;
}

const POLL_MS = 2000;

export default function DeviceLinkModal(props: DeviceLinkModalProps) {
  const [qrCode, setQrCode] = createSignal('');
  const [linkUrl, setLinkUrl] = createSignal('');
  const [pairingId, setPairingId] = createSignal('');
  const [expiresAt, setExpiresAt] = createSignal('');
  const [loading, setLoading] = createSignal(false);
  const [expired, setExpired] = createSignal(false);
  const [done, setDone] = createSignal(false);
  const [linkCopied, setLinkCopied] = createSignal(false);

  let pollTimer: ReturnType<typeof setInterval> | undefined;

  createEffect(() => {
    if (!props.open) setLinkCopied(false);
  });

  const stopPoll = () => {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
  };

  onCleanup(() => stopPoll());

  createEffect(() => {
    if (!props.open) {
      stopPoll();
      return;
    }

    let cancelled = false;
    setLoading(true);
    setExpired(false);
    setDone(false);
    stopPoll();

    (async () => {
      try {
        const keys = getCurrentKeys();
        let encOpts: { encryptedKeys?: string; encryptedKeysIv?: string; transferKey?: string } = {};
        if (keys) {
          const enc = await encryptKeyBundleForTransfer(keys);
          encOpts = { encryptedKeys: enc.encryptedKeys, encryptedKeysIv: enc.iv, transferKey: enc.transferKey };
        }

        const res = await api.createDeviceLinkSession({
          encryptedKeys: encOpts.encryptedKeys,
          encryptedKeysIv: encOpts.encryptedKeysIv,
        });
        if (cancelled) return;

        const baseLinkUrl = `${window.location.origin}/login/link#p=${encodeURIComponent(res.pairingId)}&s=${encodeURIComponent(res.linkSecret)}`;
        const fullLinkUrl = encOpts.transferKey
          ? `${baseLinkUrl}&k=${encodeURIComponent(encOpts.transferKey)}`
          : baseLinkUrl;

        const qrDataUrl = await QRCode.toDataURL(fullLinkUrl, { width: 256, margin: 2 });
        setQrCode(qrDataUrl);
        setLinkUrl(fullLinkUrl);
        setPairingId(res.pairingId);
        setExpiresAt(res.expiresAt);

        pollTimer = setInterval(async () => {
          try {
            const st = await api.getDeviceLinkStatus(res.pairingId);
            if (st.status === 'completed') {
              stopPoll();
              setDone(true);
              toast.success('Your phone signed in successfully.');
            } else if (st.status === 'expired' || st.status === 'expired_or_invalid') {
              stopPoll();
              setExpired(true);
            }
          } catch {
            /* ignore transient poll errors */
          }
        }, POLL_MS);
      } catch (e: unknown) {
        if (!cancelled) {
          toast.error(e instanceof Error ? e.message : 'Could not create link');
          props.onClose();
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      stopPoll();
    };
  });

  const copyLink = async () => {
    const url = linkUrl();
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setLinkCopied(true);
      window.setTimeout(() => setLinkCopied(false), 2000);
      toast.success('Link copied');
    } catch {
      toast.error('Could not copy');
    }
  };

  return (
    <Show when={props.open}>
      <div
        class="fixed inset-0 z-[85] flex items-end sm:items-center justify-center p-4 bg-black/70"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-link-title"
      >
        <div class="w-full max-w-md rounded-xl border border-gray-700 bg-gray-800 p-4 shadow-vault-float max-h-[90vh] overflow-y-auto">
          <div class="flex items-start justify-between gap-2 mb-3">
            <h3 id="device-link-title" class="text-lg font-medium text-white">
              Link phone or tablet
            </h3>
            <button
              type="button"
              onClick={() => props.onClose()}
              class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 shrink-0"
              aria-label="Close"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <p class="text-sm text-gray-400 mb-4">
            Scan this QR code on your phone to sign in instantly. Your encryption keys are transferred securely — no file needed on the phone.
          </p>

          <Show when={loading()}>
            <div class="flex justify-center py-12">
              <div class="animate-spin rounded-full h-10 w-10 border-2 border-primary-500/30 border-t-primary-500" />
            </div>
          </Show>

          <Show when={!loading() && qrCode()}>
            <div class="flex flex-col items-center gap-4">
              <div class="bg-white p-3 rounded-lg">
                <img src={qrCode()} alt="QR code to sign in on phone" class="w-52 h-52 sm:w-56 sm:h-56" width="224" height="224" />
              </div>
              <p class="text-xs text-gray-500 text-center">
                Expires {expiresAt() ? new Date(expiresAt()).toLocaleTimeString(undefined, { timeStyle: 'short' }) : ''}{' '}
                · pairing <code class="text-gray-400">{pairingId().slice(0, 8)}…</code>
              </p>
              <button
                type="button"
                onClick={() => copyLink()}
                class={`text-sm font-medium rounded-lg px-3 py-2 transition-colors ${
                  linkCopied()
                    ? 'bg-green-600/20 text-green-400'
                    : 'text-primary-400 hover:text-primary-300 hover:bg-gray-700/50'
                }`}
              >
                {linkCopied() ? 'Copied!' : 'Copy link (if you cannot scan)'}
              </button>
            </div>
          </Show>

          <Show when={done()}>
            <p class="text-center text-green-400 text-sm py-4">You can close this window.</p>
          </Show>

          <Show when={expired() && !done()}>
            <p class="text-center text-amber-300 text-sm py-4">This QR code expired. Close and open Link again.</p>
          </Show>

          <div class="flex justify-end mt-4">
            <button
              type="button"
              onClick={() => props.onClose()}
              class="px-4 py-2 rounded-lg text-sm bg-gray-700 hover:bg-gray-600 text-white"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
}
