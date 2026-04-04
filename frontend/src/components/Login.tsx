import { createSignal, Show, createEffect } from 'solid-js';
import { useAuth } from '../stores/auth';
import * as api from '../lib/api';
import {
  setCurrentKeys,
  importSigningPrivateKey,
  signChallenge,
  loadKeyBundleFromFile,
  type KeyBundle,
} from '../lib/crypto';
import { getFullDeviceInfo } from '../lib/deviceFingerprint';
import { awaitMinElapsed, MIN_FORM_SUBMIT_MS } from '../lib/motion';

interface LoginProps {
  onSwitchToRegister: () => void;
  /** When true, show demo key download below the login card. */
  isDemoMode?: boolean;
  /** Pre-filled username (e.g. demo_admin from server in demo mode). */
  demoUsername?: string;
}

export default function Login(props: LoginProps) {
  const { login } = useAuth();
  const [username, setUsername] = createSignal(props.demoUsername ?? '');
  const [, setKeyFile] = createSignal<File | null>(null);
  const [keyBundle, setKeyBundle] = createSignal<KeyBundle | null>(null);
  const [totp, setTotp] = createSignal('');
  const [requires2FA, setRequires2FA] = createSignal(false);
  const [challengeData, setChallengeData] = createSignal<{ challenge: string; challengeId: string } | null>(null);
  const [error, setError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);
  const [trustDevice, setTrustDevice] = createSignal(false);

  createEffect(() => {
    const u = props.demoUsername;
    if (u) setUsername(u);
  });

  const handleKeyFileChange = async (e: Event) => {
    const input = e.target as HTMLInputElement;
    if (input.files?.[0]) {
      const file = input.files[0];
      setKeyFile(file);
      setError('');
      
      try {
        const bundle = await loadKeyBundleFromFile(file);
        setKeyBundle(bundle);
      } catch (err: any) {
        setError(err.message || 'Invalid key file format');
        setKeyBundle(null);
      }
    }
  };

  const handleLogin = async (e: Event) => {
    e.preventDefault();
    setError('');
    const opStart = Date.now();
    setIsLoading(true);

    try {
      // Get device fingerprint to check if trusted
      const deviceInfo = await getFullDeviceInfo();
      
      // Step 1: Get challenge (with fingerprint to check trusted device)
      const { challenge, challengeId, requires2FA: needs2FA } = await api.getChallenge(username(), deviceInfo.fingerprint);
      
      setRequires2FA(needs2FA);
      setChallengeData({ challenge, challengeId });

      if (needs2FA && !totp()) {
        await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
        setIsLoading(false);
        return; // Wait for 2FA code
      }

      await completeLogin(challenge, challengeId);
    } catch (err: any) {
      setError(err.message || 'Login failed');
      await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
      setIsLoading(false);
    }
  };

  const completeLogin = async (challenge: string, challengeId: string) => {
    const opStart = Date.now();
    try {
      // Load keys from file
      const keys = keyBundle();
      if (!keys) {
        throw new Error('Please select your keys.json file');
      }

      // Sign challenge
      const privateKey = await importSigningPrivateKey(keys.signingPrivateKey);
      const signature = await signChallenge(privateKey, challenge);

      // Always get device info for trusted device check
      const deviceInfo = await getFullDeviceInfo();

      // Verify with server
      const result = await api.verifyLogin(
        username(),
        challengeId,
        signature,
        totp() || undefined,
        trustDevice() && requires2FA(), // Only trust if checkbox checked and 2FA enabled
        deviceInfo.fingerprint,
        deviceInfo.deviceName,
        deviceInfo.browser,
        deviceInfo.os
      );

      // Store keys in memory
      setCurrentKeys(keys);

      // Update auth state
      login(result.token, {
        ...result.user,
        totpEnabled: requires2FA(),
      });
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      await awaitMinElapsed(opStart, MIN_FORM_SUBMIT_MS);
      setIsLoading(false);
    }
  };

  const handleSubmit2FA = async (e: Event) => {
    e.preventDefault();
    if (challengeData()) {
      setIsLoading(true);
      await completeLogin(challengeData()!.challenge, challengeData()!.challengeId);
    }
  };

  return (
    <div class="max-w-md mx-auto mt-8 sm:mt-16 px-3 sm:px-0">
      <div class="bg-gray-800 rounded-xl p-4 sm:p-8 shadow-xl animate-sv-rise">
        <h2 class="text-xl sm:text-2xl font-bold text-center mb-6">Welcome Back</h2>
        
        {error() && (
          <div class="bg-red-500/20 border border-red-500 text-red-300 rounded-lg p-3 mb-4">
            {error()}
          </div>
        )}

        <form onSubmit={requires2FA() && challengeData() ? handleSubmit2FA : handleLogin}>
          <div class="mb-4">
            <label for="login-username" class="block text-gray-400 text-sm mb-2">
              Username
            </label>
            <input
              id="login-username"
              type="text"
              value={username()}
              onInput={(e) => setUsername(e.currentTarget.value)}
              class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
              placeholder="Enter your username"
              autocomplete="username"
              required
              disabled={requires2FA() && !!challengeData()}
              readOnly={!!props.demoUsername}
              title={props.demoUsername ? 'Demo account username' : undefined}
            />
          </div>

          <div class="mb-4">
            <label for="login-keyfile" class="block text-gray-400 text-sm mb-2">
              Key File (keys.json)
            </label>
            <input
              id="login-keyfile"
              type="file"
              accept=".json"
              onChange={handleKeyFileChange}
              class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-primary-600 file:text-white file:cursor-pointer"
              required
              disabled={requires2FA() && !!challengeData()}
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

          {requires2FA() && challengeData() && (
            <>
              <div class="mb-4">
                <label for="login-totp" class="block text-gray-400 text-sm mb-2">
                  2FA Code
                </label>
                <input
                  id="login-totp"
                  type="text"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  value={totp()}
                  onInput={(e) => setTotp(e.currentTarget.value)}
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
                  <span class="text-gray-400 text-sm group-hover:text-gray-300">
                    Remember this device for 30 days
                  </span>
                </label>
                <p class="text-gray-500 text-xs mt-1 ml-6">
                  You won't need to enter 2FA code on this device
                </p>
              </div>
            </>
          )}

          <button
            type="submit"
            disabled={isLoading()}
            class="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
          >
            {isLoading() ? (
              <span class="flex items-center justify-center gap-2">
                <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Authenticating...
              </span>
            ) : requires2FA() && challengeData() ? 'Verify 2FA' : 'Login'}
          </button>
        </form>

        <Show when={!props.isDemoMode}>
          <div class="mt-6 text-center">
            <p class="text-gray-400">
              Don't have an account?{' '}
              <button
                onClick={props.onSwitchToRegister}
                class="text-primary-400 hover:text-primary-300"
              >
                Register
              </button>
            </p>
          </div>
        </Show>
      </div>

      <Show when={props.isDemoMode}>
        <div class="mt-6 flex flex-col items-center gap-2">
          <a
            href="/demo_admin_keys.json"
            download="demo_admin_keys.json"
            class="inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-gray-700 hover:bg-gray-600 border border-gray-600 text-white text-sm font-medium transition-colors"
          >
            Download demo admin keys
          </a>
          <p class="text-gray-500 text-xs text-center max-w-sm">
            Sign in with the downloaded key file (username is set above).
          </p>
        </div>
      </Show>
    </div>
  );
}
