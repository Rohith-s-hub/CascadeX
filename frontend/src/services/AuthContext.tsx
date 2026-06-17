// frontend/src/services/AuthContext.tsx

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { TokenStorage, apiLogout, User } from './auth';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (user: User, tokens: { access: string; refresh: string }) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  login: () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Restore session from localStorage on app load
    const savedUser = TokenStorage.getUser();
    const token = TokenStorage.getAccess();
    if (savedUser && token) {
      setUser(savedUser);
    }
    setIsLoading(false);
  }, []);

  const login = useCallback(
    (user: User, tokens: { access: string; refresh: string }) => {
      TokenStorage.setTokens(tokens);
      TokenStorage.setUser(user);
      setUser(user);
    },
    []
  );

  const logout = useCallback(async () => {
    const refresh = TokenStorage.getRefresh();
    if (refresh) {
      try {
        await apiLogout(refresh);
      } catch (_) {}
    }
    TokenStorage.clear();
    setUser(null);
    window.location.href = '/login';
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
