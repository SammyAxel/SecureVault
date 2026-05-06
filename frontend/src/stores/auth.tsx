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
  isLoading: () => boolean;
  /** Session is HttpOnly cookie; call after login/device-link JSON succeeds so cookies are already set. */
  login: (user: User) => void;
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
    try {
      const data = await getCurrentUser();
      setUser(data.user);
      resetInactivityTimer();
    } catch {
      /* no valid session cookie */
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

  const login = (newUser: User) => {
    toast.dismissAll();
    setUser(newUser);
    resetInactivityTimer();
  };

  const logout = async () => {
    // Clear inactivity timer
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
      inactivityTimer = null;
    }

    if (user()) {
      try {
        await apiLogout();
      } catch {
        /* still clear local session */
      }
    }

    clearCurrentKeys(); // Clear encryption keys from memory and sessionStorage
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
    <AuthContext.Provider value={{ user, isLoading, login, logout, updateUser, resetInactivityTimer }}>
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
