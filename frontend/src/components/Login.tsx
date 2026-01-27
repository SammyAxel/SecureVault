import { createSignal } from 'solid-js';
import { useAuth } from '../stores/auth';
import * as api from '../lib/api';
import {
  generateKeyBundle,
  downloadKeyBundle,
  setCurrentKeys,
  importSigningPrivateKey,
  signChallenge,
} from '../lib/crypto';

interface LoginProps {
  onSwitchToRegister: () => void;
}

export default function Login(props: LoginProps) {
  const { login } = useAuth();
  const [username, setUsername] = createSignal('');
  const [keyFile, setKeyFile] = createSignal<File | null>(null);
  const [totp, setTotp] = createSignal('');
  const [requires2FA, setRequires2FA] = createSignal(false);
  const [challengeData, setChallengeData] = createSignal<{ challenge: string; challengeId: string } | null>(null);
  const [error, setError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);

  const handleKeyFileChange = (e: Event) => {
    const input = e.target as HTMLInputElement;
    if (input.files?.[0]) {
      setKeyFile(input.files[0]);
    }
  };

  const handleLogin = async (e: Event) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Step 1: Get challenge
      const { challenge, challengeId, requires2FA: needs2FA } = await api.getChallenge(username());
      
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
      if (!keyFile()) {
        throw new Error('Please select your keys.json file');
      }

      const text = await keyFile()!.text();
      const keys = JSON.parse(text);

      // Sign challenge
      const privateKey = await importSigningPrivateKey(keys.signingPrivateKey);
      const signature = await signChallenge(privateKey, challenge);

      // Verify with server
      const result = await api.verifyLogin(
        username(),
        challengeId,
        signature,
        totp() || undefined
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
          </div>

          {requires2FA() && challengeData() && (
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
          )}

          <button
            type="submit"
            disabled={isLoading()}
            class="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
          >
            {isLoading() ? 'Authenticating...' : requires2FA() && challengeData() ? 'Verify 2FA' : 'Login'}
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
