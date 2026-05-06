import { createSignal, Show, onMount } from 'solid-js';
import { useAuth } from '../stores/auth';
import * as api from '../lib/api';
import {
  setCurrentKeys,
  importSigningPrivateKey,
  signChallenge,
  decryptKeyBundleFromTransfer,
  loadKeyBundleFromFile,
  type KeyBundle,
} from '../lib/crypto';
import { getFullDeviceInfo } from '../lib/deviceFingerprint';
import { awaitMinElapsed, MIN_FORM_SUBMIT_MS } from '../lib/motion';
import { ROUTES } from '../lib/routes';

function parseLinkFromLocation(): {
  pairingId: string;
  linkSecret: string;
  transferKey: string | null;
} | null {
  const raw = window.location.hash.replace(/^#/, '');
  if (!raw) return null;
  const params = new URLSearchParams(raw);
  const p = params.get('p');
  const s = params.get('s');
  if (!p || !s) return null;
  return { pairingId: p, linkSecret: s, transferKey: params.get('k') };
}

interface DeviceLinkLoginProps {
  navigate: (path: string) => void;
  onSwitchToNormalLogin: () => void;
  onSwitchToRegister: () => void;
}

export default function DeviceLinkLogin(props: DeviceLinkLoginProps) {
  const { login } = useAuth();
  const [linkParams, setLinkParams] = createSignal<ReturnType<typeof parseLinkFromLocation>>(null);
  const [keyBundle, setKeyBundle] = createSignal<KeyBundle | null>(null);
  const [totp, setTotp] = createSignal('');
  const [requires2FA, setRequires2FA] = createSignal(false);
  const [linkedUsername, setLinkedUsername] = createSignal('');
  const [challengeData, setChallengeData] = createSignal<{
    challenge: string;
    challengeId: string;
  } | null>(null);
  const [error, setError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);
  const [trustDevice, setTrustDevice] = createSignal(false);
  const [status, setStatus] = createSignal('');

  const completeSignIn = async (
    challenge: string,
    challengeId: string,
    keys: KeyBundle,
    opStart: number
  ) => {
    const params = linkParams();
    if (!params) return;

    try {
      const privateKey = await importSigningPrivateKey(keys.signingPrivateKey);
      const signature = await signChallenge(privateKey, challenge);
      const deviceInfo = await getFullDeviceInfo();

      const result = await api.verifyDeviceLink(
        params.pairingId,
        params.linkSecret,
        challengeId,
        signature,
        {
          totp: totp() || undefined,
          trustDevice: trustDevice() && requires2FA(),
          deviceFingerprint: deviceInfo.fingerprint,
          deviceName: deviceInfo.deviceName,
          browser: deviceInfo.browser,
          os: deviceInfo.os,
        }
      );

      setCurrentKeys(keys);
      login({
        ...result.user,
        totpEnabled: requires2FA(),
      });
      window.history.replaceState({}, '', ROUTES.home);
      props.navigate(ROUTES.home);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
    } finally {
      await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
      setIsLoading(false);
    }
  };

  const startChallenge = async (keys: KeyBundle | null) => {
    setError('');
    const params = linkParams();
    if (!params) {
      setError('Invalid or missing link. Scan the QR code from your computer.');
      return;
    }

    const opStart = Date.now();
    setIsLoading(true);
    try {
      setStatus('Connecting…');
      const deviceInfo = await getFullDeviceInfo();
      const res = await api.getDeviceLinkChallenge(
        params.pairingId,
        params.linkSecret,
        deviceInfo.fingerprint
      );

      setRequires2FA(res.requires2FA);
      setLinkedUsername(res.username);
      setChallengeData({ challenge: res.challenge, challengeId: res.challengeId });

      let resolvedKeys = keys;
      if (!resolvedKeys && res.encryptedKeys && res.encryptedKeysIv && params.transferKey) {
        setStatus('Decrypting keys…');
        resolvedKeys = await decryptKeyBundleFromTransfer(
          params.transferKey,
          res.encryptedKeys,
          res.encryptedKeysIv
        );
        setKeyBundle(resolvedKeys);
      }

      if (!resolvedKeys) {
        setStatus('');
        await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
        setIsLoading(false);
        return;
      }

      if (res.requires2FA && !totp()) {
        setStatus('');
        await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
        setIsLoading(false);
        return;
      }

      setStatus('Signing in…');
      await completeSignIn(res.challenge, res.challengeId, resolvedKeys, opStart);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
      setStatus('');
      await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
      setIsLoading(false);
    }
  };

  onMount(() => {
    const params = parseLinkFromLocation();
    setLinkParams(params);
    if (params) {
      startChallenge(null);
    }
  });

  const handleKeyFileChange = async (e: Event) => {
    const input = e.target as HTMLInputElement;
    if (!input.files?.[0]) return;
    setError('');
    try {
      const bundle = await loadKeyBundleFromFile(input.files[0]);
      setKeyBundle(bundle);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid key file format');
      setKeyBundle(null);
    }
  };

  const handleManualContinue = async (e: Event) => {
    e.preventDefault();
    const keys = keyBundle();
    if (!keys) {
      setError('Please select your keys.json file first');
      return;
    }

    const data = challengeData();
    if (data && requires2FA()) {
      setIsLoading(true);
      await completeSignIn(data.challenge, data.challengeId, keys, Date.now());
    } else {
      await startChallenge(keys);
    }
  };

  const needsManualKeys = () => !linkParams()?.transferKey && !keyBundle();
  const waiting2FA = () => requires2FA() && challengeData() && keyBundle();

  return (
    <div class="max-w-md mx-auto mt-8 sm:mt-16 px-3 sm:px-0">
      <div class="bg-gray-800 rounded-xl p-4 sm:p-8 shadow-xl animate-sv-rise">
        <h2 class="text-xl sm:text-2xl font-bold text-center mb-2">Sign in with QR link</h2>

        <Show
          when={linkParams()}
          fallback={
            <div class="space-y-4">
              <div class="bg-amber-500/15 border border-amber-500/40 text-amber-200 rounded-lg p-4 text-sm">
                No QR link detected. On your computer, open SecureVault → Profile → Security → Link phone or tablet,
                then scan the QR code with this phone.
              </div>
              <button
                type="button"
                onClick={() => props.onSwitchToNormalLogin()}
                class="w-full bg-gray-700 hover:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
              >
                Use username login instead
              </button>
            </div>
          }
        >
          {error() && (
            <div class="bg-red-500/20 border border-red-500 text-red-300 rounded-lg p-3 mb-4">{error()}</div>
          )}

          <Show when={linkedUsername()}>
            <p class="text-center text-gray-300 text-sm mb-4">
              Account: <span class="text-white font-medium">{linkedUsername()}</span>
            </p>
          </Show>

          {/* Auto flow: loading + status */}
          <Show when={isLoading() && !waiting2FA()}>
            <div class="flex flex-col items-center gap-3 py-8">
              <div class="animate-spin rounded-full h-10 w-10 border-2 border-primary-500/30 border-t-primary-500" />
              <p class="text-gray-400 text-sm">{status() || 'Connecting…'}</p>
            </div>
          </Show>

          {/* 2FA step (shown if needed) */}
          <Show when={waiting2FA()}>
            <form onSubmit={handleManualContinue}>
              <p class="text-gray-400 text-sm text-center mb-4">
                Your account requires a 2FA code to complete sign-in.
              </p>
              <div class="mb-4">
                <label for="device-link-totp" class="block text-gray-400 text-sm mb-2">
                  2FA code
                </label>
                <input
                  id="device-link-totp"
                  type="text"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  value={totp()}
                  onInput={(e) =>
                    setTotp(e.currentTarget.value.replace(/\D/g, '').slice(0, 6))
                  }
                  class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500 text-center text-2xl tracking-widest"
                  placeholder="000000"
                  maxLength={6}
                  required
                />
              </div>
              <div class="mb-4">
                <label class="flex items-center gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={trustDevice()}
                    onChange={(e) => setTrustDevice(e.currentTarget.checked)}
                    class="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-500 focus:ring-primary-500 focus:ring-offset-gray-800"
                  />
                  <span class="text-gray-400 text-sm group-hover:text-gray-300">Remember this device for 30 days</span>
                </label>
              </div>
              <button
                type="submit"
                disabled={isLoading()}
                class="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
              >
                {isLoading() ? 'Signing in…' : 'Verify and sign in'}
              </button>
            </form>
          </Show>

          {/* Fallback: no transferred keys → manual file picker */}
          <Show when={!isLoading() && !waiting2FA() && needsManualKeys()}>
            <form onSubmit={handleManualContinue}>
              <p class="text-gray-400 text-sm text-center mb-4">
                Keys could not be transferred automatically. Select your <span class="text-gray-300">keys.json</span> file to continue.
              </p>
              <div class="mb-4">
                <label for="device-link-keyfile" class="block text-gray-400 text-sm mb-2">
                  Key file (keys.json)
                </label>
                <input
                  id="device-link-keyfile"
                  type="file"
                  accept=".json,application/json"
                  onChange={handleKeyFileChange}
                  class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-primary-600 file:text-white file:cursor-pointer"
                />
                <Show when={keyBundle()}>
                  <p class="text-green-400 text-xs mt-1 flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                    </svg>
                    Key file loaded
                  </p>
                </Show>
              </div>
              <button
                type="submit"
                disabled={isLoading() || !keyBundle()}
                class="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
              >
                Continue
              </button>
            </form>
          </Show>
        </Show>

        <div class="mt-6 text-center space-y-2">
          <p class="text-gray-400 text-sm">
            <button type="button" onClick={() => props.onSwitchToNormalLogin()} class="text-primary-400 hover:text-primary-300">
              Username login
            </button>
            {' · '}
            <button type="button" onClick={() => props.onSwitchToRegister()} class="text-primary-400 hover:text-primary-300">
              Register
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
