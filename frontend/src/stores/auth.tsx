import { createContext, createSignal, useContext, ParentComponent, onMount, onCleanup } from 'solid-js';
import { clearCurrentKeys } from '../lib/crypto';
import { toast } from './toast';

export interface User {
  id: number;
  username: string;
  isAdmin: boolean;
  storageUsed: number;
  storageQuota: number;
  totpEnabled: boolean;
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

export const AuthProvider: ParentComponent = (props) => {
  const [user, setUser] = createSignal<User | null>(null);
  const [token, setToken] = createSignal<string | null>(null);
  const [isLoading, setIsLoading] = createSignal(true);
  
  let inactivityTimer: ReturnType<typeof setTimeout> | null = null;

  // Reset the inactivity timer
  const resetInactivityTimer = () => {
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
    }
    
    // Only set timer if user is logged in
    if (user()) {
      inactivityTimer = setTimeout(() => {
        console.log('Auto-logout due to inactivity');
        logout();
        toast.info('You have been logged out due to inactivity.');
      }, INACTIVITY_TIMEOUT);
    }
  };

  // Activity event listener
  const handleActivity = () => {
    if (user()) {
      resetInactivityTimer();
    }
  };

  onMount(async () => {
    // Check for existing session
    const savedToken = localStorage.getItem('securevault_token');
    if (savedToken) {
      try {
        const response = await fetch('/api/me', {
          headers: { Authorization: `Bearer ${savedToken}` },
        });
        
        if (response.ok) {
          const data = await response.json();
          setToken(savedToken);
          setUser(data.user);
          resetInactivityTimer();
        } else {
          localStorage.removeItem('securevault_token');
        }
      } catch (error) {
        console.error('Session check failed:', error);
        localStorage.removeItem('securevault_token');
      }
    }
    setIsLoading(false);

    // Add activity listeners
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
    events.forEach(event => {
      document.addEventListener(event, handleActivity, { passive: true });
    });
  });

  onCleanup(() => {
    // Clean up timer and listeners
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
    }
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
    events.forEach(event => {
      document.removeEventListener(event, handleActivity);
    });
  });

  const login = (newToken: string, newUser: User) => {
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
        await fetch('/api/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${currentToken}` },
        });
      } catch (error) {
        console.error('Logout failed:', error);
      }
    }
    
    localStorage.removeItem('securevault_token');
    clearCurrentKeys(); // Clear encryption keys from memory and sessionStorage
    setToken(null);
    setUser(null);
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
