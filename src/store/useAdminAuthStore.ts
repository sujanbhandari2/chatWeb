import { create } from 'zustand';
import { ADMIN_SESSION_STORAGE_KEY } from '../constants/session.constants';

export type AdminSessionUser = {
  id: string;
  email: string;
  name: string;
};

type AdminAuthState = {
  token: string;
  user: AdminSessionUser | null;
  sessionHydrated: boolean;
  hydrate: () => void;
  setSession: (token: string, user: AdminSessionUser) => void;
  clearSession: () => void;
};

export const useAdminAuthStore = create<AdminAuthState>((set) => ({
  token: '',
  user: null,
  sessionHydrated: false,
  hydrate: () => {
    try {
      const raw = window.localStorage.getItem(ADMIN_SESSION_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as { token?: string; user?: AdminSessionUser };
        if (parsed?.token && parsed?.user) {
          set({ token: parsed.token, user: parsed.user, sessionHydrated: true });
          return;
        }
      }
    } catch {
      /* ignore */
    }
    set({ sessionHydrated: true });
  },
  setSession: (token, user) => {
    window.localStorage.setItem(ADMIN_SESSION_STORAGE_KEY, JSON.stringify({ token, user }));
    set({ token, user });
  },
  clearSession: () => {
    window.localStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
    set({ token: '', user: null });
  }
}));
