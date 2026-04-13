import { create } from 'zustand';
import { ADMIN_SESSION_STORAGE_KEY } from '../constants/admin.constants';

type AdminAuthState = {
  token: string;
  sessionHydrated: boolean;
  hydrate: () => void;
  setSession: (token: string) => void;
  clearSession: () => void;
};

export const useAdminAuthStore = create<AdminAuthState>((set) => ({
  token: '',
  sessionHydrated: false,
  hydrate: () => {
    try {
      const raw = window.localStorage.getItem(ADMIN_SESSION_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as { token?: string };
        if (parsed?.token && typeof parsed.token === 'string') {
          set({ token: parsed.token, sessionHydrated: true });
          return;
        }
      }
    } catch {
      /* ignore */
    }
    set({ sessionHydrated: true });
  },
  setSession: (token) => {
    window.localStorage.setItem(ADMIN_SESSION_STORAGE_KEY, JSON.stringify({ token }));
    set({ token });
  },
  clearSession: () => {
    window.localStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
    set({ token: '' });
  }
}));
