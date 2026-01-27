import { createSignal } from 'solid-js';
import * as api from '../lib/api';
import {
  generateKeyBundle,
  downloadKeyBundle,
} from '../lib/crypto';

interface RegisterProps {
  onSwitchToLogin: () => void;
}

export default function Register(props: RegisterProps) {
  const [username, setUsername] = createSignal('');
  const [error, setError] = createSignal('');
  const [success, setSuccess] = createSignal(false);
  const [isLoading, setIsLoading] = createSignal(false);

  const handleRegister = async (e: Event) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Validate username
      if (username().length < 3) {
        throw new Error('Username must be at least 3 characters');
      }

      if (!/^[a-zA-Z0-9_]+$/.test(username())) {
        throw new Error('Username can only contain letters, numbers, and underscores');
      }

      // Generate key bundle
      const keys = await generateKeyBundle();

      // Register with server
      await api.register(
        username(),
        keys.signingPublicKey,
        keys.encryptionPublicKey
      );

      // Download keys
      downloadKeyBundle(keys, username());

      setSuccess(true);
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  if (success()) {
    return (
      <div class="max-w-md mx-auto mt-16">
        <div class="bg-gray-800 rounded-xl p-8 shadow-xl text-center">
          <div class="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg class="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          
          <h2 class="text-2xl font-bold mb-4">Registration Successful!</h2>
          
          <div class="bg-yellow-500/20 border border-yellow-500 rounded-lg p-4 mb-6">
            <p class="text-yellow-300 text-sm">
              <strong>⚠️ Important:</strong> Your keys file has been downloaded. 
              Store it safely - you'll need it to log in. If you lose this file, 
              you will lose access to your account and all your files!
            </p>
          </div>

          <button
            onClick={props.onSwitchToLogin}
            class="w-full bg-primary-600 hover:bg-primary-700 text-white font-medium py-3 rounded-lg transition-colors"
          >
            Continue to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div class="max-w-md mx-auto mt-16">
      <div class="bg-gray-800 rounded-xl p-8 shadow-xl">
        <h2 class="text-2xl font-bold text-center mb-6">Create Account</h2>
        
        <div class="bg-blue-500/20 border border-blue-500 rounded-lg p-4 mb-6">
          <p class="text-blue-300 text-sm">
            🔐 <strong>Zero-Knowledge Registration:</strong> Your encryption keys are 
            generated in your browser. We never see your private keys.
          </p>
        </div>

        {error() && (
          <div class="bg-red-500/20 border border-red-500 text-red-300 rounded-lg p-3 mb-4">
            {error()}
          </div>
        )}

        <form onSubmit={handleRegister}>
          <div class="mb-6">
            <label class="block text-gray-400 text-sm mb-2">Username</label>
            <input
              type="text"
              value={username()}
              onInput={(e) => setUsername(e.currentTarget.value)}
              class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
              placeholder="Choose a username"
              minLength={3}
              maxLength={80}
              pattern="^[a-zA-Z0-9_]+$"
              required
            />
            <p class="text-gray-500 text-xs mt-1">
              Letters, numbers, and underscores only
            </p>
          </div>

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
                Generating Keys...
              </span>
            ) : (
              'Create Account'
            )}
          </button>
        </form>

        <div class="mt-6 text-center">
          <p class="text-gray-400">
            Already have an account?{' '}
            <button
              onClick={props.onSwitchToLogin}
              class="text-primary-400 hover:text-primary-300"
            >
              Login
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
