import { createContext, createSignal, useContext, ParentComponent, onMount } from 'solid-js';
import { clearCurrentKeys } from '../lib/crypto';

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
}

const AuthContext = createContext<AuthContextValue>();

export const AuthProvider: ParentComponent = (props) => {
  const [user, setUser] = createSignal<User | null>(null);
  const [token, setToken] = createSignal<string | null>(null);
  const [isLoading, setIsLoading] = createSignal(true);

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
        } else {
          localStorage.removeItem('securevault_token');
        }
      } catch (error) {
        console.error('Session check failed:', error);
        localStorage.removeItem('securevault_token');
      }
    }
    setIsLoading(false);
  });

  const login = (newToken: string, newUser: User) => {
    localStorage.setItem('securevault_token', newToken);
    setToken(newToken);
    setUser(newUser);
  };

  const logout = async () => {
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
    <AuthContext.Provider value={{ user, token, isLoading, login, logout, updateUser }}>
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
