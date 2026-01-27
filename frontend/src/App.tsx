import { createSignal, Show, createEffect } from 'solid-js';
import { AuthProvider, useAuth } from './stores/auth.jsx';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import PublicShare from './components/PublicShare';
import AdminDashboard from './components/AdminDashboard';
import ToastContainer from './components/Toast';
import ConfirmModal from './components/ConfirmModal';

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
  const { path, navigate } = useRoute();
  
  // Check if we're on a public share page
  const isPublicShare = () => path().startsWith('/share/');
  
  // Check if we're on admin page
  const isAdminPage = () => path() === '/admin';

  // If on public share page, render just that
  if (isPublicShare()) {
    return <PublicShare />;
  }

  return (
    <div class="min-h-screen bg-gray-900">
      {/* Header */}
      <header class="bg-gray-800 border-b border-gray-700">
        <div class="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div class="flex items-center gap-3">
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
              <span class="text-gray-400">Welcome, <span class="text-white font-medium">{user()?.username}</span></span>
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
            {/* Admin Dashboard or User Dashboard */}
            <Show when={isAdminPage() && user()?.isAdmin} fallback={<Dashboard />}>
              <AdminDashboard />
            </Show>
          </Show>
        </Show>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
      <ToastContainer />
      <ConfirmModal />
    </AuthProvider>
  );
}
