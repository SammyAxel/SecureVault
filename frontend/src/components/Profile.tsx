import { createSignal, createEffect, For, Show, onMount } from 'solid-js';
import { useAuth } from '../stores/auth';
import * as api from '../lib/api';
import { toast } from '../stores/toast';
import { openConfirm } from '../stores/confirm';
import {
  generateEncryptedKeyBundle,
  downloadKeyBundle,
  getCurrentKeys,
  isEncryptedKeyBundle,
} from '../lib/crypto';

interface ProfileProps {
  onBack: () => void;
}

// Tab type
type ProfileTab = 'general' | 'security' | 'sessions' | 'danger';

export default function Profile(props: ProfileProps) {
  const { user, updateUser, logout } = useAuth();
  const [activeTab, setActiveTab] = createSignal<ProfileTab>('general');

  return (
    <div class="max-w-4xl mx-auto">
      {/* Header */}
      <div class="flex items-center gap-4 mb-6">
        <button
          onClick={props.onBack}
          class="p-2 hover:bg-gray-700 rounded-lg transition-colors"
        >
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
        </button>
        <h1 class="text-2xl font-bold">Profile Settings</h1>
      </div>

      {/* Tabs */}
      <div class="flex gap-2 mb-6 border-b border-gray-700">
        <TabButton 
          active={activeTab() === 'general'} 
          onClick={() => setActiveTab('general')}
          icon={<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
          </svg>}
        >
          General
        </TabButton>
        <TabButton 
          active={activeTab() === 'security'} 
          onClick={() => setActiveTab('security')}
          icon={<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>}
        >
          Security
        </TabButton>
        <TabButton 
          active={activeTab() === 'sessions'} 
          onClick={() => setActiveTab('sessions')}
          icon={<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>}
        >
          Sessions
        </TabButton>
        <TabButton 
          active={activeTab() === 'danger'} 
          onClick={() => setActiveTab('danger')}
          icon={<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>}
          danger
        >
          Danger Zone
        </TabButton>
      </div>

      {/* Tab Content */}
      <Show when={activeTab() === 'general'}>
        <GeneralTab />
      </Show>
      <Show when={activeTab() === 'security'}>
        <SecurityTab />
      </Show>
      <Show when={activeTab() === 'sessions'}>
        <SessionsTab />
      </Show>
      <Show when={activeTab() === 'danger'}>
        <DangerTab onLogout={logout} />
      </Show>
    </div>
  );
}

// Tab Button Component
function TabButton(props: { 
  active: boolean; 
  onClick: () => void; 
  children: any;
  icon?: any;
  danger?: boolean;
}) {
  return (
    <button
      onClick={props.onClick}
      class={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
        props.active
          ? props.danger 
            ? 'border-red-500 text-red-400' 
            : 'border-primary-500 text-white'
          : 'border-transparent text-gray-400 hover:text-gray-300'
      }`}
    >
      {props.icon}
      {props.children}
    </button>
  );
}

// ============ GENERAL TAB ============
function GeneralTab() {
  const { user, updateUser } = useAuth();
  const [displayName, setDisplayName] = createSignal(user()?.displayName || '');
  const [avatar, setAvatar] = createSignal(user()?.avatar || '');
  const [isLoading, setIsLoading] = createSignal(false);

  const handleAvatarChange = async (e: Event) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    // Validate file
    if (!file.type.startsWith('image/')) {
      toast.error('Please select an image file');
      return;
    }

    if (file.size > 500 * 1024) {
      toast.error('Image too large (max 500KB)');
      return;
    }

    // Convert to base64
    const reader = new FileReader();
    reader.onload = () => {
      setAvatar(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const removeAvatar = () => {
    setAvatar('');
  };

  const handleSave = async () => {
    setIsLoading(true);
    try {
      await api.updateProfile({
        displayName: displayName() || undefined,
        avatar: avatar() || undefined,
      });
      
      updateUser({
        displayName: displayName() || undefined,
        avatar: avatar() || undefined,
      });
      
      toast.success('Profile updated successfully');
    } catch (err: any) {
      toast.error(err.message || 'Failed to update profile');
    } finally {
      setIsLoading(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const storagePercent = () => {
    const used = user()?.storageUsed || 0;
    const quota = user()?.storageQuota || 1;
    return Math.min((used / quota) * 100, 100);
  };

  return (
    <div class="space-y-6">
      {/* Avatar Section */}
      <div class="bg-gray-800 rounded-xl p-6">
        <h3 class="text-lg font-semibold mb-4">Profile Picture</h3>
        
        <div class="flex items-center gap-6">
          <div class="relative">
            <div class="w-24 h-24 rounded-full bg-gray-700 flex items-center justify-center overflow-hidden">
              <Show when={avatar()} fallback={
                <span class="text-3xl font-bold text-gray-400">
                  {user()?.username?.charAt(0).toUpperCase()}
                </span>
              }>
                <img src={avatar()} alt="Avatar" class="w-full h-full object-cover" />
              </Show>
            </div>
          </div>
          
          <div class="flex flex-col gap-2">
            <label class="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg cursor-pointer transition-colors text-center">
              Upload Photo
              <input
                type="file"
                accept="image/*"
                onChange={handleAvatarChange}
                class="hidden"
              />
            </label>
            <Show when={avatar()}>
              <button
                onClick={removeAvatar}
                class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
              >
                Remove
              </button>
            </Show>
            <p class="text-gray-500 text-xs">Max 500KB, JPG/PNG/GIF</p>
          </div>
        </div>
      </div>

      {/* Display Name */}
      <div class="bg-gray-800 rounded-xl p-6">
        <h3 class="text-lg font-semibold mb-4">Display Name</h3>
        
        <div class="max-w-md">
          <input
            type="text"
            value={displayName()}
            onInput={(e) => setDisplayName(e.currentTarget.value)}
            class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
            placeholder={user()?.username}
            maxLength={50}
          />
          <p class="text-gray-500 text-xs mt-2">
            This will be shown instead of your username. Leave empty to use username.
          </p>
        </div>
      </div>

      {/* Account Info */}
      <div class="bg-gray-800 rounded-xl p-6">
        <h3 class="text-lg font-semibold mb-4">Account Information</h3>
        
        <div class="space-y-4">
          <div class="flex justify-between">
            <span class="text-gray-400">Username</span>
            <span class="text-white font-medium">{user()?.username}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Account Type</span>
            <span class={`font-medium ${user()?.isAdmin ? 'text-primary-400' : 'text-white'}`}>
              {user()?.isAdmin ? 'Administrator' : 'User'}
            </span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Member Since</span>
            <span class="text-white">
              {user()?.createdAt ? new Date(user()!.createdAt!).toLocaleDateString() : 'N/A'}
            </span>
          </div>
        </div>
      </div>

      {/* Storage */}
      <div class="bg-gray-800 rounded-xl p-6">
        <h3 class="text-lg font-semibold mb-4">Storage</h3>
        
        <div class="space-y-3">
          <div class="flex justify-between text-sm">
            <span class="text-gray-400">
              {formatBytes(user()?.storageUsed || 0)} used
            </span>
            <span class="text-gray-400">
              {formatBytes(user()?.storageQuota || 0)} total
            </span>
          </div>
          <div class="h-3 bg-gray-700 rounded-full overflow-hidden">
            <div 
              class={`h-full transition-all ${
                storagePercent() > 90 ? 'bg-red-500' : 
                storagePercent() > 70 ? 'bg-yellow-500' : 'bg-primary-500'
              }`}
              style={{ width: `${storagePercent()}%` }}
            />
          </div>
          <p class="text-gray-500 text-xs">
            {storagePercent().toFixed(1)}% of storage used
          </p>
        </div>
      </div>

      {/* Save Button */}
      <div class="flex justify-end">
        <button
          onClick={handleSave}
          disabled={isLoading()}
          class="px-6 py-3 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white font-medium rounded-lg transition-colors"
        >
          {isLoading() ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  );
}

// ============ SECURITY TAB ============
function SecurityTab() {
  const { user, updateUser } = useAuth();
  const [show2FASetup, setShow2FASetup] = createSignal(false);
  const [qrCode, setQrCode] = createSignal('');
  const [secret, setSecret] = createSignal('');
  const [totpCode, setTotpCode] = createSignal('');
  const [backupCodes, setBackupCodes] = createSignal<string[]>([]);
  const [isLoading, setIsLoading] = createSignal(false);
  const [disableCode, setDisableCode] = createSignal('');
  
  // Password reset state
  const [newPassword, setNewPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [isGeneratingKeys, setIsGeneratingKeys] = createSignal(false);

  const setup2FA = async () => {
    setIsLoading(true);
    try {
      const result = await api.setup2FA();
      setQrCode(result.qrCode);
      setSecret(result.secret);
      setShow2FASetup(true);
    } catch (err: any) {
      toast.error(err.message || 'Failed to setup 2FA');
    } finally {
      setIsLoading(false);
    }
  };

  const confirm2FA = async () => {
    if (totpCode().length !== 6) {
      toast.error('Please enter a 6-digit code');
      return;
    }
    
    setIsLoading(true);
    try {
      const result = await api.confirm2FA(totpCode());
      setBackupCodes(result.backupCodes);
      updateUser({ totpEnabled: true });
      toast.success('2FA enabled successfully!');
    } catch (err: any) {
      toast.error(err.message || 'Invalid code');
    } finally {
      setIsLoading(false);
    }
  };

  const disable2FA = async () => {
    if (disableCode().length !== 6) {
      toast.error('Please enter your 2FA code');
      return;
    }

    setIsLoading(true);
    try {
      await api.disable2FA(disableCode());
      updateUser({ totpEnabled: false });
      setShow2FASetup(false);
      setDisableCode('');
      toast.success('2FA disabled');
    } catch (err: any) {
      toast.error(err.message || 'Invalid code');
    } finally {
      setIsLoading(false);
    }
  };

  const regenerateKeys = async () => {
    if (newPassword().length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }
    
    if (newPassword() !== confirmPassword()) {
      toast.error('Passwords do not match');
      return;
    }

    openConfirm({
      title: 'Regenerate Encryption Keys?',
      message: 'This will generate new encryption keys. Your old key file will no longer work, and you will NOT be able to decrypt files encrypted with your old keys. Are you absolutely sure?',
      confirmText: 'Regenerate Keys',
      type: 'danger',
      onConfirm: async () => {
        setIsGeneratingKeys(true);
        try {
          const { bundle } = await generateEncryptedKeyBundle(newPassword());
          downloadKeyBundle(bundle, user()!.username);
          toast.success('New keys generated! Please save your new key file.');
          setNewPassword('');
          setConfirmPassword('');
        } catch (err: any) {
          toast.error(err.message || 'Failed to generate keys');
        } finally {
          setIsGeneratingKeys(false);
        }
      },
    });
  };

  return (
    <div class="space-y-6">
      {/* 2FA Section */}
      <div class="bg-gray-800 rounded-xl p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="text-lg font-semibold">Two-Factor Authentication</h3>
            <p class="text-gray-400 text-sm mt-1">
              Add an extra layer of security to your account
            </p>
          </div>
          <div class={`px-3 py-1 rounded-full text-sm ${
            user()?.totpEnabled 
              ? 'bg-green-500/20 text-green-400' 
              : 'bg-gray-700 text-gray-400'
          }`}>
            {user()?.totpEnabled ? 'Enabled' : 'Disabled'}
          </div>
        </div>

        <Show when={!user()?.totpEnabled}>
          <Show when={!show2FASetup()}>
            <button
              onClick={setup2FA}
              disabled={isLoading()}
              class="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors"
            >
              {isLoading() ? 'Setting up...' : 'Enable 2FA'}
            </button>
          </Show>

          <Show when={show2FASetup()}>
            <Show when={backupCodes().length === 0}>
              <div class="space-y-4">
                <div class="flex items-start gap-6">
                  <div class="bg-white p-3 rounded-lg">
                    <img src={qrCode()} alt="QR Code" class="w-40 h-40" />
                  </div>
                  <div class="flex-1">
                    <p class="text-gray-300 mb-3">
                      Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
                    </p>
                    <div class="bg-gray-700 rounded-lg p-3">
                      <p class="text-xs text-gray-400 mb-1">Manual entry code:</p>
                      <code class="text-sm text-primary-400 break-all">{secret()}</code>
                    </div>
                  </div>
                </div>

                <div class="max-w-xs">
                  <label class="block text-gray-400 text-sm mb-2">Enter 6-digit code</label>
                  <input
                    type="text"
                    value={totpCode()}
                    onInput={(e) => setTotpCode(e.currentTarget.value.replace(/\D/g, '').slice(0, 6))}
                    class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white text-center text-2xl tracking-widest focus:outline-none focus:border-primary-500"
                    placeholder="000000"
                    maxLength={6}
                  />
                </div>

                <div class="flex gap-3">
                  <button
                    onClick={confirm2FA}
                    disabled={isLoading() || totpCode().length !== 6}
                    class="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 text-white rounded-lg transition-colors"
                  >
                    {isLoading() ? 'Verifying...' : 'Verify & Enable'}
                  </button>
                  <button
                    onClick={() => setShow2FASetup(false)}
                    class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </Show>

            {/* Show backup codes after successful setup */}
            <Show when={backupCodes().length > 0}>
              <div class="bg-yellow-500/20 border border-yellow-500 rounded-lg p-4 mb-4">
                <h4 class="text-yellow-300 font-semibold mb-2">⚠️ Save Your Backup Codes!</h4>
                <p class="text-yellow-200 text-sm mb-4">
                  Store these codes safely. You can use them to access your account if you lose your authenticator.
                </p>
                <div class="grid grid-cols-2 gap-2 mb-4">
                  <For each={backupCodes()}>
                    {(code) => (
                      <code class="bg-gray-800 px-3 py-2 rounded text-center font-mono">{code}</code>
                    )}
                  </For>
                </div>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(backupCodes().join('\n'));
                    toast.success('Backup codes copied!');
                  }}
                  class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  Copy All Codes
                </button>
              </div>
              <button
                onClick={() => {
                  setShow2FASetup(false);
                  setBackupCodes([]);
                }}
                class="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors"
              >
                Done
              </button>
            </Show>
          </Show>
        </Show>

        {/* Disable 2FA */}
        <Show when={user()?.totpEnabled}>
          <div class="space-y-4">
            <p class="text-gray-400 text-sm">
              To disable 2FA, enter your current authenticator code.
            </p>
            <div class="flex gap-3 items-end">
              <div class="flex-1 max-w-xs">
                <input
                  type="text"
                  value={disableCode()}
                  onInput={(e) => setDisableCode(e.currentTarget.value.replace(/\D/g, '').slice(0, 6))}
                  class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white text-center text-xl tracking-widest focus:outline-none focus:border-primary-500"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>
              <button
                onClick={disable2FA}
                disabled={isLoading() || disableCode().length !== 6}
                class="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg transition-colors"
              >
                {isLoading() ? 'Disabling...' : 'Disable 2FA'}
              </button>
            </div>
          </div>
        </Show>
      </div>

      {/* Regenerate Keys Section */}
      <div class="bg-gray-800 rounded-xl p-6">
        <h3 class="text-lg font-semibold mb-2">Encryption Keys</h3>
        <p class="text-gray-400 text-sm mb-4">
          Generate new password-protected encryption keys. Use this if you forgot your password or want to change it.
        </p>
        
        <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-4">
          <p class="text-red-300 text-sm">
            <strong>⚠️ Warning:</strong> Regenerating keys will make all your previously encrypted files unreadable. Only do this if you've lost your old keys.
          </p>
        </div>

        <div class="space-y-4 max-w-md">
          <div>
            <label class="block text-gray-400 text-sm mb-2">New Master Password</label>
            <input
              type="password"
              value={newPassword()}
              onInput={(e) => setNewPassword(e.currentTarget.value)}
              class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
              placeholder="Enter new password"
              minLength={8}
            />
          </div>
          <div>
            <label class="block text-gray-400 text-sm mb-2">Confirm Password</label>
            <input
              type="password"
              value={confirmPassword()}
              onInput={(e) => setConfirmPassword(e.currentTarget.value)}
              class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary-500"
              placeholder="Confirm new password"
            />
          </div>
          <button
            onClick={regenerateKeys}
            disabled={isGeneratingKeys() || newPassword().length < 8 || newPassword() !== confirmPassword()}
            class="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 text-white rounded-lg transition-colors"
          >
            {isGeneratingKeys() ? 'Generating...' : 'Generate New Keys'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============ SESSIONS TAB ============
function SessionsTab() {
  const [sessions, setSessions] = createSignal<api.SessionInfo[]>([]);
  const [isLoading, setIsLoading] = createSignal(true);

  onMount(async () => {
    await loadSessions();
  });

  const loadSessions = async () => {
    setIsLoading(true);
    try {
      const result = await api.getSessions();
      setSessions(result.sessions);
    } catch (err: any) {
      toast.error('Failed to load sessions');
    } finally {
      setIsLoading(false);
    }
  };

  const revokeSession = async (id: number) => {
    try {
      await api.revokeSession(id);
      setSessions(sessions().filter(s => s.id !== id));
      toast.success('Session revoked');
    } catch (err: any) {
      toast.error(err.message || 'Failed to revoke session');
    }
  };

  const revokeAllOthers = async () => {
    openConfirm({
      title: 'Revoke All Other Sessions?',
      message: 'This will log you out from all other devices. Only your current session will remain active.',
      confirmText: 'Revoke All',
      type: 'danger',
      onConfirm: async () => {
        try {
          await api.revokeAllSessions();
          await loadSessions();
          toast.success('All other sessions revoked');
        } catch (err: any) {
          toast.error(err.message || 'Failed to revoke sessions');
        }
      },
    });
  };

  const parseUserAgent = (ua?: string): { browser: string; os: string } => {
    if (!ua) return { browser: 'Unknown', os: 'Unknown' };
    
    let browser = 'Unknown';
    let os = 'Unknown';
    
    // Detect browser
    if (ua.includes('Chrome')) browser = 'Chrome';
    else if (ua.includes('Firefox')) browser = 'Firefox';
    else if (ua.includes('Safari')) browser = 'Safari';
    else if (ua.includes('Edge')) browser = 'Edge';
    
    // Detect OS
    if (ua.includes('Windows')) os = 'Windows';
    else if (ua.includes('Mac')) os = 'macOS';
    else if (ua.includes('Linux')) os = 'Linux';
    else if (ua.includes('Android')) os = 'Android';
    else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
    
    return { browser, os };
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleString();
  };

  return (
    <div class="space-y-6">
      <div class="bg-gray-800 rounded-xl p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="text-lg font-semibold">Active Sessions</h3>
            <p class="text-gray-400 text-sm mt-1">
              Manage devices where you're logged in
            </p>
          </div>
          <button
            onClick={revokeAllOthers}
            class="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg transition-colors text-sm"
          >
            Revoke All Others
          </button>
        </div>

        <Show when={isLoading()}>
          <div class="flex justify-center py-8">
            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
          </div>
        </Show>

        <Show when={!isLoading()}>
          <div class="space-y-3">
            <For each={sessions()}>
              {(session) => {
                const { browser, os } = parseUserAgent(session.userAgent);
                return (
                  <div class={`flex items-center justify-between p-4 rounded-lg ${
                    session.isCurrent ? 'bg-primary-500/10 border border-primary-500/30' : 'bg-gray-700'
                  }`}>
                    <div class="flex items-center gap-4">
                      <div class="w-10 h-10 bg-gray-600 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                        </svg>
                      </div>
                      <div>
                        <div class="flex items-center gap-2">
                          <span class="font-medium">{browser} on {os}</span>
                          <Show when={session.isCurrent}>
                            <span class="px-2 py-0.5 bg-primary-500/20 text-primary-400 text-xs rounded-full">
                              Current
                            </span>
                          </Show>
                        </div>
                        <div class="text-gray-400 text-sm">
                          {session.ipAddress || 'Unknown IP'} • Last active: {formatDate(session.lastActive)}
                        </div>
                      </div>
                    </div>
                    
                    <Show when={!session.isCurrent}>
                      <button
                        onClick={() => revokeSession(session.id)}
                        class="p-2 hover:bg-red-500/20 text-red-400 rounded-lg transition-colors"
                        title="Revoke session"
                      >
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>
    </div>
  );
}

// ============ DANGER TAB ============
function DangerTab(props: { onLogout: () => void }) {
  const { user } = useAuth();
  const [confirmation, setConfirmation] = createSignal('');
  const [isDeleting, setIsDeleting] = createSignal(false);

  const handleDeleteAccount = async () => {
    if (confirmation() !== user()?.username) {
      toast.error('Please type your username correctly');
      return;
    }

    openConfirm({
      title: 'Delete Account Permanently?',
      message: 'This action cannot be undone. All your files, shares, and data will be permanently deleted.',
      confirmText: 'Delete Forever',
      type: 'danger',
      onConfirm: async () => {
        setIsDeleting(true);
        try {
          await api.deleteAccount(confirmation());
          toast.success('Account deleted');
          props.onLogout();
        } catch (err: any) {
          toast.error(err.message || 'Failed to delete account');
        } finally {
          setIsDeleting(false);
        }
      },
    });
  };

  return (
    <div class="space-y-6">
      <div class="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
        <h3 class="text-lg font-semibold text-red-400 mb-2">Delete Account</h3>
        <p class="text-gray-300 mb-4">
          Once you delete your account, there is no going back. This will permanently delete:
        </p>
        <ul class="list-disc list-inside text-gray-400 text-sm mb-6 space-y-1">
          <li>Your profile and settings</li>
          <li>All your uploaded files</li>
          <li>All your shared files and links</li>
          <li>All your sessions</li>
        </ul>

        <div class="max-w-md mb-4">
          <label class="block text-gray-400 text-sm mb-2">
            Type <strong class="text-white">{user()?.username}</strong> to confirm
          </label>
          <input
            type="text"
            value={confirmation()}
            onInput={(e) => setConfirmation(e.currentTarget.value)}
            class="w-full bg-gray-800 border border-red-500/30 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-red-500"
            placeholder="Enter your username"
          />
        </div>

        <button
          onClick={handleDeleteAccount}
          disabled={isDeleting() || confirmation() !== user()?.username}
          class="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white font-medium rounded-lg transition-colors"
        >
          {isDeleting() ? 'Deleting...' : 'Delete My Account'}
        </button>
      </div>
    </div>
  );
}
