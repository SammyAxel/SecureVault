import { createSignal, Show } from 'solid-js';
import { useAuth } from '../stores/auth';
import * as api from '../lib/api';
import {
  setCurrentKeys,
  importSigningPrivateKey,
  signChallenge,
  isEncryptedKeyBundle,
  decryptKeyBundle,
  type KeyBundle,
  type EncryptedKeyBundle,
} from '../lib/crypto';
import { getFullDeviceInfo } from '../lib/deviceFingerprint';

interface LoginProps {
  onSwitchToRegister: () => void;
}

export default function Login(props: LoginProps) {
  const { login } = useAuth();
  const [username, setUsername] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [showPassword, setShowPassword] = createSignal(false);
  const [keyFile, setKeyFile] = createSignal<File | null>(null);
  const [keyBundle, setKeyBundle] = createSignal<KeyBundle | EncryptedKeyBundle | null>(null);
  const [isEncrypted, setIsEncrypted] = createSignal(false);
  const [totp, setTotp] = createSignal('');
  const [requires2FA, setRequires2FA] = createSignal(false);
  const [challengeData, setChallengeData] = createSignal<{ challenge: string; challengeId: string } | null>(null);
  const [error, setError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);
  const [decryptingKeys, setDecryptingKeys] = createSignal(false);
  const [trustDevice, setTrustDevice] = createSignal(false);

  const handleKeyFileChange = async (e: Event) => {
    const input = e.target as HTMLInputElement;
    if (input.files?.[0]) {
      const file = input.files[0];
      setKeyFile(file);
      setError('');
      
      try {
        const text = await file.text();
        const bundle = JSON.parse(text);
        setKeyBundle(bundle);
        
        // Check if this is an encrypted key bundle
        const encrypted = isEncryptedKeyBundle(bundle);
        setIsEncrypted(encrypted);
        
        if (!encrypted) {
          // Legacy format - no password needed
          setPassword('');
        }
      } catch (err) {
        setError('Invalid key file format');
        setKeyBundle(null);
        setIsEncrypted(false);
      }
    }
  };

  const handleLogin = async (e: Event) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Get device fingerprint to check if trusted
      const deviceInfo = await getFullDeviceInfo();
      
      // Step 1: Get challenge (with fingerprint to check trusted device)
      const { challenge, challengeId, requires2FA: needs2FA } = await api.getChallenge(username(), deviceInfo.fingerprint);
      
      setRequires2FA(needs2FA);
      setChallengeData({ challenge, challengeId });

      if (needs2FA && !totp()) {
        setIsLoading(false);
        return; // Wait for 2FA code
      }

      await completeLogin(challenge, challengeId);
    } catch (err: any) {
      setError(err.message || 'Login failed');
      setIsLoading(false);
    }
  };

  const completeLogin = async (challenge: string, challengeId: string) => {
    try {
      // Load keys from file
      if (!keyBundle()) {
        throw new Error('Please select your keys.json file');
      }

      let keys: KeyBundle;
      
      // Handle encrypted vs legacy key bundles
      if (isEncrypted()) {
        if (!password()) {
          throw new Error('Password is required to decrypt your keys');
        }
        
        setDecryptingKeys(true);
        try {
          keys = await decryptKeyBundle(keyBundle() as EncryptedKeyBundle, password());
        } catch (err: any) {
          if (err.message.includes('decrypt')) {
            throw new Error('Incorrect password. Please try again.');
          }
          throw err;
        } finally {
          setDecryptingKeys(false);
        }
      } else {
        // Legacy unencrypted format
        keys = keyBundle() as KeyBundle;
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
      setIsLoading(false);
      setDecryptingKeys(false);
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
    <div class="max-w-md mx-auto mt-16">
      <div class="bg-gray-800 rounded-xl p-8 shadow-xl">
        <h2 class="text-2xl font-bold text-center mb-6">Welcome Back</h2>
        
        {error() && (
          <div class="bg-red-500/20 border border-red-500 text-red-300 rounded-lg p-3 mb-4">
            {error()}
          </div>
        )}

        <form onSubmit={requires2FA() && challengeData() ? handleSubmit2FA : handleLogin}>
          <div class="mb-4">
            <label class="block text-gray-400 text-sm mb-2">Username</label>
            <input
              type="text"
              value={username()}
              onInput={(e) => setUsername(e.currentTarget.value)}
              class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
              placeholder="Enter your username"
              required
              disabled={requires2FA() && !!challengeData()}
            />
          </div>

          <div class="mb-4">
            <label class="block text-gray-400 text-sm mb-2">Key File (keys.json)</label>
            <input
              type="file"
              accept=".json"
              onChange={handleKeyFileChange}
              class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-primary-600 file:text-white file:cursor-pointer"
              required
              disabled={requires2FA() && !!challengeData()}
            />
            <Show when={keyBundle() && isEncrypted()}>
              <p class="text-green-400 text-xs mt-1 flex items-center gap-1">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                Password-protected key file detected
              </p>
            </Show>
            <Show when={keyBundle() && !isEncrypted()}>
              <p class="text-yellow-400 text-xs mt-1 flex items-center gap-1">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Legacy unencrypted key file (consider re-registering for better security)
              </p>
            </Show>
          </div>

          {/* Password field for encrypted keys */}
          <Show when={isEncrypted()}>
            <div class="mb-4">
              <label class="block text-gray-400 text-sm mb-2">Master Password</label>
              <div class="relative">
                <input
                  type={showPassword() ? 'text' : 'password'}
                  value={password()}
                  onInput={(e) => setPassword(e.currentTarget.value)}
                  class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 pr-12 text-white focus:outline-none focus:border-primary-500"
                  placeholder="Enter your master password"
                  required
                  disabled={requires2FA() && !!challengeData()}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword())}
                  class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  <Show when={showPassword()} fallback={
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  }>
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                    </svg>
                  </Show>
                </button>
              </div>
              <p class="text-gray-500 text-xs mt-1">
                The password you used when creating your account
              </p>
            </div>
          </Show>

          {requires2FA() && challengeData() && (
            <>
              <div class="mb-4">
                <label class="block text-gray-400 text-sm mb-2">2FA Code</label>
                <input
                  type="text"
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
            disabled={isLoading() || (isEncrypted() && !password())}
            class="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
          >
            {isLoading() ? (
              <span class="flex items-center justify-center gap-2">
                <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                {decryptingKeys() ? 'Decrypting Keys...' : 'Authenticating...'}
              </span>
            ) : requires2FA() && challengeData() ? 'Verify 2FA' : 'Login'}
          </button>
        </form>

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
      </div>
    </div>
  );
}
