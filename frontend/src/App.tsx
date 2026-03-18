import { createSignal, Show, createEffect, onMount } from 'solid-js';
import { AuthProvider, useAuth } from './stores/auth.jsx';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import Profile from './components/Profile';
import AdminDashboard from './components/AdminDashboard';
import Setup from './components/Setup';
import ToastContainer from './components/Toast';
import ConfirmModal from './components/ConfirmModal';
import PublicShare from './components/PublicShare';
import FileViewer from './components/FileViewer';
import * as api from './lib/api';

// Simple path-based routing
function useRoute() {
  const [path, setPath] = createSignal(window.location.pathname);
  
  createEffect(() => {
    const handlePopState = () => setPath(window.location.pathname);
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  });
  
  const navigate = (newPath: string) => {
    window.history.pushState({}, '', newPath);
    setPath(newPath);
  };
  
  return { path, navigate };
}

function AppContent() {
  const { user, isLoading, logout } = useAuth();
  const [showRegister, setShowRegister] = createSignal(false);
  const [needsSetup, setNeedsSetup] = createSignal(false);
  const [checkingSetup, setCheckingSetup] = createSignal(true);
  const { path, navigate } = useRoute();
  
  // Check if we're on admin page
  const isAdminPage = () => path() === '/admin';
  
  // Check if we're on profile page
  const isProfilePage = () => path() === '/profile';

  // Extract UID from /f/:uid path (folder view)
  const getUIDFromPath = () => {
    const match = path().match(/^\/f\/([a-zA-Z0-9-]+)/);
    return match ? match[1] : null;
  };

  // Sync path with login/register view: /login -> Login, /register -> Register
  createEffect(() => {
    const p = path();
    if (p === '/login') setShowRegister(false);
    else if (p === '/register') setShowRegister(true);
  });

  // After login (or when already logged in on auth pages), redirect to home so URL is proper
  createEffect(() => {
    if (!user()) return;
    const p = path();
    if (p === '/login' || p === '/register') navigate('/');
  });

  // When not logged in and on a protected path (e.g. /), redirect to /login
  createEffect(() => {
    if (checkingSetup() || needsSetup()) return;
    if (user() || getUIDFromPath()) return;
    const p = path();
    if (p === '/' || p === '/admin' || p === '/profile') {
      navigate('/login');
    }
  });

  // Check setup status and register auth:logout listener on mount
  onMount(() => {
    const handleLogout = () => navigate('/login');
    window.addEventListener('auth:logout', handleLogout);

    (async () => {
      try {
        const status = await api.checkSetupStatus();
        setNeedsSetup(status.needsSetup);
      } catch (err) {
        console.error('Failed to check setup status:', err);
        setNeedsSetup(false);
      } finally {
        setCheckingSetup(false);
      }
    })();

    return () => window.removeEventListener('auth:logout', handleLogout);
  });

  return (
    <>
      {/* Loading state */}
      <Show when={checkingSetup()}>
        <div class="min-h-screen bg-gray-900 flex items-center justify-center">
          <div class="text-center">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
            <p class="text-gray-400">Loading SecureVault...</p>
          </div>
        </div>
      </Show>

      {/* Setup wizard */}
      <Show when={!checkingSetup() && needsSetup()}>
        <Setup onComplete={() => setNeedsSetup(false)} />
      </Show>

      {/* Main app */}
      <Show when={!checkingSetup() && !needsSetup()}>
        {/* Folder view - Google Drive style */}
        <Show when={getUIDFromPath()}>
          <Show when={isLoading()}>
            <div class="min-h-screen bg-gray-900 flex items-center justify-center">
              <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
            </div>
          </Show>
          <Show when={!isLoading()}>
            <Show when={user()} fallback={
              <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
                <div class="bg-gray-800 rounded-xl p-6 text-center max-w-md">
                  <h2 class="text-xl font-semibold text-white mb-2">Login Required</h2>
                  <p class="text-gray-400 mb-4">Sign in to access this folder</p>
                  <button
                    onClick={() => navigate('/login')}
                    class="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg"
                  >
                    Go to Login
                  </button>
                </div>
              </div>
            }>
              <FileViewer uid={getUIDFromPath()!} navigate={navigate} />
            </Show>
          </Show>
        </Show>
        
        {/* Regular Routes - Show full drive UI */}
        <Show when={!getUIDFromPath()}>
        <div class="min-h-screen bg-gray-900">
      {/* Header */}
      <header class="bg-gray-800 border-b border-gray-700">
        <div class="max-w-7xl mx-auto px-3 sm:px-4 py-3 sm:py-4 flex items-center justify-between gap-2 flex-wrap">
          <div 
            class="flex items-center gap-2 sm:gap-3 cursor-pointer min-w-0 shrink-0"
            onClick={() => navigate('/')}
          >
            <div class="w-9 h-9 sm:w-10 sm:h-10 bg-primary-600 rounded-lg flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 sm:w-6 sm:h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 class="text-lg sm:text-xl font-bold text-white truncate">SecureVault</h1>
          </div>
          
          <Show when={user()}>
            <div class="flex items-center gap-2 sm:gap-4 shrink-0">
              {/* Admin link: icon-only on small screens */}
              <Show when={user()?.isAdmin}>
                <button
                  onClick={() => navigate(isAdminPage() ? '/' : '/admin')}
                  class={`p-2 sm:px-3 sm:py-1.5 rounded-lg text-sm flex items-center gap-2 touch-target sm:min-h-0 ${
                    isAdminPage() 
                      ? 'bg-primary-600 text-white' 
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                  title={isAdminPage() ? 'Exit Admin' : 'Admin'}
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  <span class="hidden md:inline">{isAdminPage() ? 'Exit Admin' : 'Admin'}</span>
                </button>
              </Show>
              
              {/* Profile section (Discord-style) with dropdown */}
              <ProfileSection
                user={user()!}
                isProfilePage={isProfilePage()}
                onNavigate={navigate}
                onLogout={logout}
              />
            </div>
          </Show>
        </div>
      </header>

      {/* Main Content */}
      <main class="max-w-7xl mx-auto px-3 sm:px-4 py-4 sm:py-8">
        <Show when={isLoading()}>
          <div class="flex items-center justify-center h-64">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
          </div>
        </Show>

        <Show when={!isLoading()}>
          <Show when={user()} fallback={
            <Show when={showRegister()} fallback={
              <Login onSwitchToRegister={() => navigate('/register')} />
            }>
              <Register onSwitchToLogin={() => navigate('/login')} />
            </Show>
          }>
            {/* Profile Page */}
            <Show when={isProfilePage()}>
              <Profile onBack={() => navigate('/')} />
            </Show>
            
            {/* Admin Dashboard */}
            <Show when={isAdminPage() && user()?.isAdmin && !isProfilePage()}>
              <AdminDashboard navigate={navigate} />
            </Show>
            
            {/* User Dashboard (default) */}
            <Show when={!isAdminPage() && !isProfilePage()}>
              <Dashboard navigate={navigate} />
            </Show>
          </Show>
        </Show>
      </main>
        </div>
        </Show>
      </Show>
    </>
  );
}

const DROPDOWN_DURATION_MS = 200;

// Profile section with dropdown (Discord-style: user info + Logout at bottom)
function ProfileSection(props: {
  user: { username: string; displayName?: string; avatar?: string };
  isProfilePage: boolean;
  onNavigate: (path: string) => void;
  onLogout: () => void;
}) {
  const [open, setOpen] = createSignal(false);
  const [closing, setClosing] = createSignal(false);
  let closeTimeout: ReturnType<typeof setTimeout> | undefined;
  let containerRef: HTMLDivElement | undefined;

  const closeDropdown = () => {
    if (!open()) return;
    setOpen(false);
    setClosing(true);
    if (closeTimeout) clearTimeout(closeTimeout);
    closeTimeout = setTimeout(() => setClosing(false), DROPDOWN_DURATION_MS);
  };

  const handleClickOutside = (e: MouseEvent) => {
    if (containerRef && !containerRef.contains(e.target as Node)) closeDropdown();
  };

  onMount(() => {
    document.addEventListener('click', handleClickOutside);
    return () => {
      document.removeEventListener('click', handleClickOutside);
      if (closeTimeout) clearTimeout(closeTimeout);
    };
  });

  const visible = () => open() || closing();

  return (
    <div class="relative" ref={containerRef}>
      <button
        type="button"
        onClick={() => (open() ? closeDropdown() : setOpen(true))}
        class={`flex items-center gap-2 p-2 sm:px-3 sm:py-1.5 rounded-lg transition-colors duration-200 touch-target sm:min-h-0 ${
          props.isProfilePage ? 'bg-primary-600 text-white' : 'hover:bg-gray-700 text-gray-300'
        }`}
        title={props.user.displayName || props.user.username}
      >
        <div class="w-8 h-8 rounded-full bg-gray-600 flex items-center justify-center overflow-hidden shrink-0">
          <Show when={props.user.avatar} fallback={
            <span class="text-sm font-medium text-gray-300">
              {props.user.username?.charAt(0).toUpperCase()}
            </span>
          }>
            <img src={props.user.avatar} alt="Avatar" class="w-full h-full object-cover" />
          </Show>
        </div>
        <span class="text-gray-300 max-w-[100px] sm:max-w-[120px] truncate hidden sm:inline">
          {props.user.displayName || props.user.username}
        </span>
        <svg
          class={`w-4 h-4 text-gray-400 shrink-0 transition-transform duration-200 ${visible() ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <Show when={visible()}>
        <div
          class={`absolute right-0 top-full mt-1 w-56 max-w-[calc(100vw-1.5rem)] rounded-lg bg-gray-800 border border-gray-700 shadow-xl py-1 z-50 ${closing() ? 'animate-dropdown-out' : 'animate-dropdown-in'}`}
          role="menu"
        >
          {/* User info at top */}
          <div class="px-3 py-2 border-b border-gray-700">
            <div class="flex items-center gap-2">
              <div class="w-9 h-9 rounded-full bg-gray-600 flex items-center justify-center overflow-hidden shrink-0">
                <Show when={props.user.avatar} fallback={
                  <span class="text-sm font-medium text-gray-300">
                    {props.user.username?.charAt(0).toUpperCase()}
                  </span>
                }>
                  <img src={props.user.avatar} alt="" class="w-full h-full object-cover" />
                </Show>
              </div>
              <div class="min-w-0">
                <p class="text-sm font-medium text-white truncate">
                  {props.user.displayName || props.user.username}
                </p>
                <p class="text-xs text-gray-400 truncate">{props.user.username}</p>
              </div>
            </div>
          </div>
          {/* Profile Settings */}
          <button
            type="button"
            onClick={() => { props.onNavigate(props.isProfilePage ? '/' : '/profile'); closeDropdown(); }}
            class="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 hover:text-white flex items-center gap-2 transition-colors duration-150"
            role="menuitem"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            {props.isProfilePage ? 'Back to Drive' : 'Profile Settings'}
          </button>
          {/* Logout at bottom */}
          <div class="border-t border-gray-700 mt-1 pt-1">
            <button
              type="button"
              onClick={() => { props.onLogout(); closeDropdown(); }}
              class="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-red-600/20 flex items-center gap-2 transition-colors duration-150"
              role="menuitem"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1z" />
              </svg>
              Log Out
            </button>
          </div>
        </div>
      </Show>
    </div>
  );
}

export default function App() {
  // Check for public routes that don't need auth
  const isShareRoute = () => window.location.pathname.startsWith('/share/');
  
  // Render public share page
  if (isShareRoute()) {
    return <PublicShare />;
  }
  
  return (
    <AuthProvider>
      <AppContent />
      <ToastContainer />
      <ConfirmModal />
    </AuthProvider>
  );
}
