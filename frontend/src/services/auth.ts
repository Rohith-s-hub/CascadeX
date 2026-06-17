// frontend/src/services/auth.ts

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '') + '/api';

export interface AuthTokens {
  access: string;
  refresh: string;
}

export interface User {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  organization: string;
}

export interface AuthResponse {
  success: boolean;
  tokens: AuthTokens;
  user: User;
  errors?: Record<string, string[]>;
}

// ── Token storage ──────────────────────────────────────────
export const TokenStorage = {
  getAccess: () => localStorage.getItem('cascadex_access'),
  getRefresh: () => localStorage.getItem('cascadex_refresh'),
  setTokens: (tokens: AuthTokens) => {
    localStorage.setItem('cascadex_access', tokens.access);
    localStorage.setItem('cascadex_refresh', tokens.refresh);
  },
  clear: () => {
    localStorage.removeItem('cascadex_access');
    localStorage.removeItem('cascadex_refresh');
    localStorage.removeItem('cascadex_user');
  },
  getUser: (): User | null => {
    const u = localStorage.getItem('cascadex_user');
    return u ? JSON.parse(u) : null;
  },
  setUser: (user: User) => {
    localStorage.setItem('cascadex_user', JSON.stringify(user));
  },
};

// ── API helpers ────────────────────────────────────────────
export async function apiLogin(
  username: string,
  password: string
): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/login/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return res.json();
}

export async function apiRegister(data: {
  username: string;
  email: string;
  password: string;
  password_confirm: string;
  first_name: string;
  last_name: string;
  organization?: string;
}): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/register/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function apiLogout(refreshToken: string): Promise<void> {
  await fetch(`${API_BASE}/auth/logout/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TokenStorage.getAccess()}`,
    },
    body: JSON.stringify({ refresh: refreshToken }),
  });
}

export async function apiRefreshToken(): Promise<string | null> {
  const refresh = TokenStorage.getRefresh();
  if (!refresh) return null;

  const res = await fetch(`${API_BASE}/auth/token/refresh/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh }),
  });

  if (!res.ok) {
    TokenStorage.clear();
    return null;
  }

  const data = await res.json();
  if (data.tokens?.access) {
    localStorage.setItem('cascadex_access', data.tokens.access);
    return data.tokens.access;
  }
  return null;
}

// ── Authenticated fetch wrapper ────────────────────────────
export async function authFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  let token = TokenStorage.getAccess();

  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`,
    },
  });

  // Token expired — try refresh
  if (res.status === 401) {
    const newToken = await apiRefreshToken();
    if (newToken) {
      return fetch(url, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {}),
          Authorization: `Bearer ${newToken}`,
        },
      });
    }
    // Refresh also failed — redirect to login
    TokenStorage.clear();
    window.location.href = '/login';
  }

  return res;
}
