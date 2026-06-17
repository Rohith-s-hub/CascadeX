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
    // ── OAuth Callback Handler ───────────────────────────────
    // Backend redirects here with tokens in URL hash after Google/GitHub OAuth:
    // /dashboard#oauth_success=1&access=...&refresh=...&user_id=...&email=...
    const hash = window.location.hash;
    if (hash.includes('oauth_success=1')) {
      const params = new URLSearchParams(hash.substring(1));
      const access = params.get('access');
      const refresh = params.get('refresh');
      const userId = params.get('user_id');
      const username = params.get('username');
      const email = params.get('email');
      const firstName = params.get('first_name');

      if (access && refresh && userId) {
        const oauthUser: User = {
          id: parseInt(userId, 10),
          username: username || email || '',
          email: email || '',
          first_name: firstName || '',
          last_name: '',
          role: 'viewer',
          organization: '',
        };
        TokenStorage.setTokens({ access, refresh });
        TokenStorage.setUser(oauthUser);
        setUser(oauthUser);
        // Clean the URL — remove the hash so refreshes don't re-process
        window.history.replaceState(null, '', window.location.pathname);
        setIsLoading(false);
        return;
      }
    }

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
