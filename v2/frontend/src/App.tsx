import { createSignal, Show, createEffect } from 'solid-js';
import { AuthProvider, useAuth } from './stores/auth.jsx';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import PublicShare from './components/PublicShare';

// Simple path-based routing
function useRoute() {
  const [path, setPath] = createSignal(window.location.pathname);
  
  createEffect(() => {
    const handlePopState = () => setPath(window.location.pathname);
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  });
  
  return path;
}

function AppContent() {
  const { user, isLoading } = useAuth();
  const [showRegister, setShowRegister] = createSignal(false);
  const path = useRoute();
  
  // Check if we're on a public share page
  const isPublicShare = () => path().startsWith('/share/');

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
              <span class="text-gray-400">Welcome, <span class="text-white font-medium">{user()?.username}</span></span>
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
            <Dashboard />
          </Show>
        </Show>
      </main>

      {/* Footer */}
      <footer class="fixed bottom-0 left-0 right-0 bg-gray-800 border-t border-gray-700 py-3">
        <div class="max-w-7xl mx-auto px-4 text-center text-gray-500 text-sm">
          <p>🔒 End-to-End Encrypted • Zero-Knowledge Architecture • Your files, your keys</p>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
