import { createSignal, Show } from 'solid-js';
import * as api from '../lib/api';
import {
  generateEncryptedKeyBundle,
  downloadKeyBundle,
} from '../lib/crypto';

interface RegisterProps {
  onSwitchToLogin: () => void;
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

export default function Register(props: RegisterProps) {
  const [username, setUsername] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [showPassword, setShowPassword] = createSignal(false);
  const [error, setError] = createSignal('');
  const [success, setSuccess] = createSignal(false);
  const [isLoading, setIsLoading] = createSignal(false);

  const passwordStrength = () => checkPasswordStrength(password());
  const passwordsMatch = () => password() === confirmPassword();

  const handleRegister = async (e: Event) => {
    e.preventDefault();
    setError('');

    // Validate password
    if (password().length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (!passwordsMatch()) {
      setError('Passwords do not match');
      return;
    }

    if (passwordStrength().score < 2) {
      setError('Password is too weak. Use a mix of letters, numbers, and symbols.');
      return;
    }

    setIsLoading(true);

    try {
      // Validate username
      if (username().length < 3) {
        throw new Error('Username must be at least 3 characters');
      }

      if (!/^[a-zA-Z0-9_]+$/.test(username())) {
        throw new Error('Username can only contain letters, numbers, and underscores');
      }

      // Generate password-encrypted key bundle
      const { bundle, plainKeys } = await generateEncryptedKeyBundle(password());

      // Register with server
      await api.register(
        username(),
        plainKeys.signingPublicKey,
        plainKeys.encryptionPublicKey
      );

      // Download encrypted keys
      downloadKeyBundle(bundle, username());

      setSuccess(true);
      props.onSwitchToLogin();
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
          
          <div class="bg-yellow-500/20 border border-yellow-500 rounded-lg p-4 mb-4">
            <p class="text-yellow-300 text-sm">
              <strong>⚠️ Important:</strong> Your encrypted keys file has been downloaded. 
              Store it safely - you'll need it to log in.
            </p>
          </div>

          <div class="bg-green-500/20 border border-green-500 rounded-lg p-4 mb-6">
            <p class="text-green-300 text-sm">
              <strong>🔐 Enhanced Security:</strong> Your private keys are encrypted with your password. 
              Even if someone gets your keys file, they cannot use it without your password!
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
            🔐 <strong>Password-Protected Keys:</strong> Your encryption keys will be 
            encrypted with your password before download. Even if stolen, they're useless without your password.
          </p>
        </div>

        {error() && (
          <div class="bg-red-500/20 border border-red-500 text-red-300 rounded-lg p-3 mb-4">
            {error()}
          </div>
        )}

        <form onSubmit={handleRegister}>
          <div class="mb-4">
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
            {isLoading() ? (
              <span class="flex items-center justify-center gap-2">
                <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Generating & Encrypting Keys...
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
