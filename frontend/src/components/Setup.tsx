import { createSignal, Show } from 'solid-js';
import * as api from '../lib/api';
import {
  generateKeyBundle,
  downloadKeyBundle,
} from '../lib/crypto';

interface SetupProps {
  onComplete: () => void;
}

export default function Setup(props: SetupProps) {
  const [step, setStep] = createSignal<'welcome' | 'create' | 'success'>('welcome');
  const [username, setUsername] = createSignal('');
  const [virusTotalApiKey, setVirusTotalApiKey] = createSignal('');
  const [error, setError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);

  const handleCreateAdmin = async (e: Event) => {
    e.preventDefault();
    setError('');

    // Validate
    if (username().length < 3) {
      setError('Username must be at least 3 characters');
      return;
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username())) {
      setError('Username can only contain letters, numbers, and underscores');
      return;
    }

    setIsLoading(true);

    try {
      // Generate key bundle
      const keys = await generateKeyBundle();

      // Create admin account (optional VirusTotal API key for malware scan on upload)
      await api.setupAdmin(
        username(),
        keys.signingPublicKey,
        keys.encryptionPublicKey,
        virusTotalApiKey().trim() || undefined
      );

      // Download keys file
      downloadKeyBundle(keys, username());

      setStep('success');
    } catch (err: any) {
      setError(err.message || 'Setup failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4 fixed inset-0 z-50">
      {/* Welcome screen */}
      <Show when={step() === 'welcome'}>
        <div class="max-w-lg w-full relative z-10">
          <div class="text-center mb-8">
            <div class="w-20 h-20 bg-primary-600 rounded-2xl flex items-center justify-center mx-auto mb-6">
              <svg class="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 class="text-4xl font-bold text-white mb-2">Welcome to SecureVault</h1>
            <p class="text-gray-400 text-lg">End-to-End Encrypted File Storage</p>
          </div>

          <div class="bg-gray-800 rounded-xl p-8 shadow-xl">
            <h2 class="text-xl font-semibold mb-4">🚀 First-Time Setup</h2>
            
            <div class="space-y-4 text-gray-300 mb-6">
              <p>
                It looks like this is a fresh installation. Let's set up your admin account.
              </p>
              
              <div class="bg-primary-500/10 border border-primary-500/30 rounded-lg p-4">
                <h3 class="font-medium text-primary-400 mb-2">What you'll do:</h3>
                <ul class="list-disc list-inside space-y-1 text-sm">
                  <li>Create an admin username</li>
                  <li>Download your key file</li>
                </ul>
              </div>

              <div class="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                <h3 class="font-medium text-yellow-400 mb-2">⚠️ Important:</h3>
                <p class="text-sm">
                  Your encryption keys will be stored in a file. 
                  <strong> Keep this file safe!</strong> Without it, you cannot access your account.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setStep('create')}
              class="w-full bg-primary-600 hover:bg-primary-700 text-white font-medium py-3 rounded-lg transition-colors cursor-pointer"
            >
              Begin Setup
            </button>
          </div>

          <p class="text-center text-gray-500 text-sm mt-6">
            SecureVault v2 — Zero-Knowledge Encryption
          </p>
        </div>
      </Show>

      {/* Create admin form */}
      <Show when={step() === 'create'}>
        <div class="max-w-md w-full">
          <div class="text-center mb-6">
            <div class="w-16 h-16 bg-primary-600 rounded-xl flex items-center justify-center mx-auto mb-4">
              <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 class="text-2xl font-bold text-white">Create Admin Account</h1>
            <p class="text-gray-400">Step 1 of 1</p>
          </div>

          <div class="bg-gray-800 rounded-xl p-8 shadow-xl">
            <Show when={error()}>
              <div class="bg-red-500/20 border border-red-500 text-red-300 rounded-lg p-3 mb-4">
                {error()}
              </div>
            </Show>

            <form onSubmit={handleCreateAdmin}>
              <div class="mb-4">
                <label class="block text-gray-400 text-sm mb-2">Admin Username</label>
                <input
                  type="text"
                  value={username()}
                  onInput={(e) => setUsername(e.currentTarget.value)}
                  class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
                  placeholder="admin"
                  minLength={3}
                  maxLength={80}
                  pattern="^[a-zA-Z0-9_]+$"
                  required
                />
                <p class="text-gray-500 text-xs mt-1">
                  Letters, numbers, and underscores only
                </p>
              </div>

              <div class="mb-4">
                <label class="block text-gray-400 text-sm mb-2">VirusTotal API key (optional)</label>
                <input
                  type="password"
                  value={virusTotalApiKey()}
                  onInput={(e) => setVirusTotalApiKey(e.currentTarget.value)}
                  class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
                  placeholder="Leave empty to skip malware scan"
                  autocomplete="off"
                />
                <p class="text-gray-500 text-xs mt-1">
                  Enables malware scanning on upload via VirusTotal. You can add or change this later in Admin → Settings.
                </p>
              </div>

              <button
                type="submit"
                disabled={isLoading()}
                class="w-full mb-6 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
              >
                <Show when={isLoading()} fallback="Create Admin Account">
                  <span class="flex items-center justify-center gap-2">
                    <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Creating Admin Account...
                  </span>
                </Show>
              </button>
            </form>

            <button
              type="button"
              onClick={() => setStep('welcome')}
              class="w-full mt-4 text-gray-400 hover:text-white text-sm"
            >
              ← Back
            </button>
          </div>
        </div>
      </Show>

      {/* Success screen */}
      <Show when={step() === 'success'}>
        <div class="max-w-md w-full">
          <div class="bg-gray-800 rounded-xl p-8 shadow-xl text-center">
            <div class="w-20 h-20 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <svg class="w-10 h-10 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            
            <h2 class="text-2xl font-bold mb-2">Setup Complete! 🎉</h2>
            <p class="text-gray-400 mb-6">Your SecureVault admin account has been created.</p>
            
            <div class="bg-yellow-500/20 border border-yellow-500 rounded-lg p-4 mb-6">
              <p class="text-yellow-300 text-sm">
                <strong>⚠️ Important:</strong> Your keys file has been downloaded. 
                Store it safely — you'll need it to log in!
              </p>
            </div>

            <div class="bg-gray-700 rounded-lg p-4 mb-6 text-left">
              <h3 class="font-medium text-white mb-2">What's next?</h3>
              <ul class="text-sm text-gray-300 space-y-1">
                <li>✓ Log in with your admin account</li>
                <li>✓ Upload and encrypt your files</li>
                <li>✓ Invite other users to register</li>
                <li>✓ Manage users from the Admin panel</li>
              </ul>
            </div>

            <button
              type="button"
              onClick={props.onComplete}
              class="w-full bg-primary-600 hover:bg-primary-700 text-white font-medium py-3 rounded-lg transition-colors"
            >
              Continue to Login
            </button>
          </div>
        </div>
      </Show>
    </div>
  );
}
