import { create } from 'zustand';
import type { AuthUser } from '../types/chat';
import { SESSION_STORAGE_KEY } from '../constants/session.constants';

type AuthState = {
  token: string;
  user: AuthUser | null;
  sessionHydrated: boolean;
  hydrate: () => void;
  setSession: (token: string, user: AuthUser) => void;
  clearSession: () => void;
};

export const useAuthStore = create<AuthState>((set) => ({
  token: '',
  user: null,
  sessionHydrated: false,
  hydrate: () => {
    try {
      const raw = window.localStorage.getItem(SESSION_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as { token?: string; user?: AuthUser };
        if (parsed?.user) {
          const t = typeof parsed.token === 'string' ? parsed.token : '';
          const raw = parsed.user as AuthUser & { tenantId?: string };
          const user: AuthUser = {
            id: raw.id,
            name: raw.name,
            email: raw.email,
            companyId: raw.companyId ?? raw.tenantId ?? '',
            status: raw.status
          };
          set({ token: t, user, sessionHydrated: true });
          return;
        }
      }
    } catch {
      /* ignore */
    }
    set({ sessionHydrated: true });
  },
  setSession: (token, user) => {
    window.localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ token, user }));
    set({ token, user });
  },
  clearSession: () => {
    window.localStorage.removeItem(SESSION_STORAGE_KEY);
    set({ token: '', user: null });
  }
}));
