import { createContext, createSignal, useContext, ParentComponent, onMount, onCleanup } from 'solid-js';
import { clearCurrentKeys } from '../lib/crypto';
import { awaitMinElapsed, MIN_BOOTSTRAP_MS } from '../lib/motion';
import { getCurrentUser, logout as apiLogout } from '../lib/api';
import { logger } from '../lib/logger';
import { toast } from './toast';

export interface User {
  id: string;
  username: string;
  displayName?: string;
  avatar?: string;
  isAdmin: boolean;
  storageUsed: number;
  storageQuota: number;
  totpEnabled: boolean;
  createdAt?: string;
  /** True when the server runs with DEMO_MODE (restricted UI and APIs). */
  demoMode?: boolean;
}

interface AuthContextValue {
  user: () => User | null;
  token: () => string | null;
  isLoading: () => boolean;
  login: (token: string, user: User) => void;
  logout: () => Promise<void>;
  updateUser: (user: Partial<User>) => void;
  resetInactivityTimer: () => void;
}

const AuthContext = createContext<AuthContextValue>();

// Inactivity timeout: 15 minutes
const INACTIVITY_TIMEOUT = 15 * 60 * 1000;
/** mousemove fires very often; only reset the idle timer at this interval */
const MOUSEMOVE_THROTTLE_MS = 2000;

export const AuthProvider: ParentComponent = (props) => {
  const [user, setUser] = createSignal<User | null>(null);
  const [token, setToken] = createSignal<string | null>(null);
  const [isLoading, setIsLoading] = createSignal(true);
  
  let inactivityTimer: ReturnType<typeof setTimeout> | null = null;
  let lastMousemoveReset = 0;

  // Reset the inactivity timer
  const resetInactivityTimer = () => {
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
    }
    
    // Only set timer if user is logged in
    if (user()) {
      inactivityTimer = setTimeout(() => {
        logger.debug('Auto-logout due to inactivity');
        logout();
        // Persistent toast (duration 0 = stays until user dismisses)
        toast.info('You have been logged out due to inactivity. Please sign in again.', 0);
      }, INACTIVITY_TIMEOUT);
    }
  };

  const handleActivity = () => {
    if (user()) {
      resetInactivityTimer();
    }
  };

  const handleMouseMoveThrottled = () => {
    if (!user()) return;
    const now = Date.now();
    if (now - lastMousemoveReset < MOUSEMOVE_THROTTLE_MS) return;
    lastMousemoveReset = now;
    resetInactivityTimer();
  };

  onMount(async () => {
    const bootStarted = Date.now();
    // Check for existing session
    const savedToken = localStorage.getItem('securevault_token');
    if (savedToken) {
      try {
        const data = await getCurrentUser();
        setToken(savedToken);
        setUser(data.user);
        resetInactivityTimer();
      } catch {
        localStorage.removeItem('securevault_token');
      }
    }
    await awaitMinElapsed(bootStarted, MIN_BOOTSTRAP_MS);
    setIsLoading(false);

    const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'] as const;
    events.forEach((event) => {
      document.addEventListener(event, handleActivity, { passive: true });
    });
    document.addEventListener('mousemove', handleMouseMoveThrottled, { passive: true });
  });

  onCleanup(() => {
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
    }
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'] as const;
    events.forEach((event) => {
      document.removeEventListener(event, handleActivity);
    });
    document.removeEventListener('mousemove', handleMouseMoveThrottled);
  });

  const login = (newToken: string, newUser: User) => {
    toast.dismissAll();
    localStorage.setItem('securevault_token', newToken);
    setToken(newToken);
    setUser(newUser);
    resetInactivityTimer();
  };

  const logout = async () => {
    // Clear inactivity timer
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
      inactivityTimer = null;
    }
    
    const currentToken = token();
    if (currentToken) {
      try {
        await apiLogout();
      } catch {
        /* still clear local session */
      }
    }
    
    localStorage.removeItem('securevault_token');
    clearCurrentKeys(); // Clear encryption keys from memory and sessionStorage
    setToken(null);
    setUser(null);
    window.dispatchEvent(new CustomEvent('auth:logout'));
  };

  const updateUser = (updates: Partial<User>) => {
    const current = user();
    if (current) {
      setUser({ ...current, ...updates });
    }
  };

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login, logout, updateUser, resetInactivityTimer }}>
      {props.children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
