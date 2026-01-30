import { createSignal, Show } from 'solid-js';
import * as api from '../lib/api';
import {
  generateEncryptedKeyBundle,
  downloadKeyBundle,
} from '../lib/crypto';

interface SetupProps {
  onComplete: () => void;
}

// Password strength checker
function checkPasswordStrength(password: string): { score: number; label: string; color: string } {
  let score = 0;
  
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  
  if (score <= 1) return { score, label: 'Weak', color: 'bg-red-500' };
  if (score <= 2) return { score, label: 'Fair', color: 'bg-orange-500' };
  if (score <= 3) return { score, label: 'Good', color: 'bg-yellow-500' };
  if (score <= 4) return { score, label: 'Strong', color: 'bg-green-500' };
  return { score, label: 'Very Strong', color: 'bg-green-600' };
}

export default function Setup(props: SetupProps) {
  const [step, setStep] = createSignal<'welcome' | 'create' | 'success'>('welcome');
  const [username, setUsername] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [showPassword, setShowPassword] = createSignal(false);
  const [virusTotalApiKey, setVirusTotalApiKey] = createSignal('');
  const [error, setError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);

  const passwordStrength = () => checkPasswordStrength(password());
  const passwordsMatch = () => password() === confirmPassword();

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

    if (password().length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (!passwordsMatch()) {
      setError('Passwords do not match');
      return;
    }

    if (passwordStrength().score < 3) {
      setError('Password is too weak. Use a mix of uppercase, lowercase, numbers, and symbols.');
      return;
    }

    setIsLoading(true);

    try {
      // Generate password-encrypted key bundle
      const { bundle, plainKeys } = await generateEncryptedKeyBundle(password());

      // Create admin account (optional VirusTotal API key for malware scan on upload)
      await api.setupAdmin(
        username(),
        plainKeys.signingPublicKey,
        plainKeys.encryptionPublicKey,
        virusTotalApiKey().trim() || undefined
      );

      // Download encrypted keys
      downloadKeyBundle(bundle, username());

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
                  <li>Set a master password for your encryption keys</li>
                  <li>Download your encrypted key file</li>
                </ul>
              </div>

              <div class="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                <h3 class="font-medium text-yellow-400 mb-2">⚠️ Important:</h3>
                <p class="text-sm">
                  Your encryption keys will be stored in a file protected by your password. 
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
                <label class="block text-gray-400 text-sm mb-2">Master Password</label>
                <div class="relative">
                  <input
                    type={showPassword() ? 'text' : 'password'}
                    value={password()}
                    onInput={(e) => setPassword(e.currentTarget.value)}
                    class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 pr-12 text-white focus:outline-none focus:border-primary-500"
                    placeholder="Create a strong password"
                    minLength={8}
                    required
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
                {/* Password strength indicator */}
                <Show when={password().length > 0}>
                  <div class="mt-2">
                    <div class="flex gap-1 mb-1">
                      {[1, 2, 3, 4, 5].map((i) => (
                        <div 
                          class={`h-1 flex-1 rounded ${i <= passwordStrength().score ? passwordStrength().color : 'bg-gray-600'}`}
                        />
                      ))}
                    </div>
                    <p class={`text-xs ${passwordStrength().score >= 3 ? 'text-green-400' : 'text-yellow-400'}`}>
                      Password strength: {passwordStrength().label}
                    </p>
                  </div>
                </Show>
                <p class="text-gray-500 text-xs mt-1">
                  This password encrypts your private keys. Choose wisely!
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

              <div class="mb-6">
                <label class="block text-gray-400 text-sm mb-2">Confirm Password</label>
                <input
                  type={showPassword() ? 'text' : 'password'}
                  value={confirmPassword()}
                  onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                  class={`w-full bg-gray-700 border rounded-lg px-4 py-3 text-white focus:outline-none ${
                    confirmPassword() && !passwordsMatch() 
                      ? 'border-red-500 focus:border-red-500' 
                      : 'border-gray-600 focus:border-primary-500'
                  }`}
                  placeholder="Confirm your password"
                  required
                />
                <Show when={confirmPassword() && !passwordsMatch()}>
                  <p class="text-red-400 text-xs mt-1">Passwords do not match</p>
                </Show>
              </div>

              <button
                type="submit"
                disabled={isLoading() || !passwordsMatch() || password().length < 8}
                class="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition-colors"
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
            
            <div class="bg-yellow-500/20 border border-yellow-500 rounded-lg p-4 mb-4">
              <p class="text-yellow-300 text-sm">
                <strong>⚠️ Important:</strong> Your encrypted keys file has been downloaded. 
                Store it safely — you'll need it to log in!
              </p>
            </div>

            <div class="bg-green-500/20 border border-green-500 rounded-lg p-4 mb-6">
              <p class="text-green-300 text-sm">
                <strong>🔐 Security Note:</strong> Your private keys are encrypted with your password. 
                Even if someone gets your keys file, they cannot use it without your password.
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
