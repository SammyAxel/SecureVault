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
  
  // Extract UID from /f/:uid path
  const getUIDFromPath = () => {
    const match = path().match(/^\/f\/([a-zA-Z0-9]+)/);
    return match ? match[1] : null;
  };

  // Check setup status on mount
  onMount(async () => {
    try {
      const status = await api.checkSetupStatus();
      setNeedsSetup(status.needsSetup);
    } catch (err) {
      console.error('Failed to check setup status:', err);
      setNeedsSetup(false); // Assume setup is done if check fails
    } finally {
      setCheckingSetup(false);
    }
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
        {/* UID Route - Show dedicated file viewer */}
        <Show when={getUIDFromPath()}>
          <Show when={isLoading()}>
            <div class="min-h-screen bg-gray-900 flex items-center justify-center">
              <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
            </div>
          </Show>
          <Show when={!isLoading()}>
            <Show when={user()} fallback={
              <UIDAccessDenied navigate={navigate} />
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
        <div class="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div 
            class="flex items-center gap-3 cursor-pointer"
            onClick={() => navigate('/')}
          >
            <div class="w-10 h-10 bg-primary-600 rounded-lg flex items-center justify-center">
              <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 class="text-xl font-bold text-white">SecureVault</h1>
          </div>
          
          <Show when={user()}>
            <div class="flex items-center gap-4">
              {/* Admin link */}
              <Show when={user()?.isAdmin}>
                <button
                  onClick={() => navigate(isAdminPage() ? '/' : '/admin')}
                  class={`px-3 py-1.5 rounded-lg text-sm flex items-center gap-2 ${
                    isAdminPage() 
                      ? 'bg-primary-600 text-white' 
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  {isAdminPage() ? 'Exit Admin' : 'Admin'}
                </button>
              </Show>
              
              {/* User menu with avatar */}
              <button
                onClick={() => navigate(isProfilePage() ? '/' : '/profile')}
                class={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors ${
                  isProfilePage() 
                    ? 'bg-primary-600 text-white' 
                    : 'hover:bg-gray-700'
                }`}
              >
                <div class="w-8 h-8 rounded-full bg-gray-600 flex items-center justify-center overflow-hidden">
                  <Show when={user()?.avatar} fallback={
                    <span class="text-sm font-medium text-gray-300">
                      {user()?.username?.charAt(0).toUpperCase()}
                    </span>
                  }>
                    <img src={user()?.avatar} alt="Avatar" class="w-full h-full object-cover" />
                  </Show>
                </div>
                <span class="text-gray-300">
                  {user()?.displayName || user()?.username}
                </span>
              </button>
              
              <button
                onClick={() => logout()}
                class="px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg text-sm"
              >
                Logout
              </button>
            </div>
          </Show>
        </div>
      </header>

      {/* Main Content */}
      <main class="max-w-7xl mx-auto px-4 py-8">
        <Show when={isLoading()}>
          <div class="flex items-center justify-center h-64">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
          </div>
        </Show>

        <Show when={!isLoading()}>
          <Show when={user()} fallback={
            <Show when={showRegister()} fallback={
              <Login onSwitchToRegister={() => setShowRegister(true)} />
            }>
              <Register onSwitchToLogin={() => setShowRegister(false)} />
            </Show>
          }>
            {/* Profile Page */}
            <Show when={isProfilePage()}>
              <Profile onBack={() => navigate('/')} />
            </Show>
            
            {/* Admin Dashboard */}
            <Show when={isAdminPage() && user()?.isAdmin && !isProfilePage()}>
              <AdminDashboard />
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

// Component shown when user is not logged in but tries to access a UID link
function UIDAccessDenied(props: { navigate: (path: string) => void }) {
  const [showLogin, setShowLogin] = createSignal(true);
  
  return (
    <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div class="bg-gray-800 rounded-xl shadow-2xl max-w-md w-full overflow-hidden">
        <div class="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4 text-center">
          <div class="w-16 h-16 bg-white/20 rounded-full flex items-center justify-center mx-auto mb-3">
            <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 class="text-xl font-bold text-white">Login Required</h1>
          <p class="text-primary-100 text-sm mt-1">Sign in to access this file</p>
        </div>
        
        <div class="p-6">
          <Show when={showLogin()} fallback={
            <Register onSwitchToLogin={() => setShowLogin(true)} />
          }>
            <Login onSwitchToRegister={() => setShowLogin(false)} />
          </Show>
        </div>
      </div>
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
