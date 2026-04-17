/** Admin console (react-router) — separate from widget embed. */
export const ADMIN_SESSION_STORAGE_KEY = 'healthchat.admin.session';

/** Session-scoped list of clients created from this browser (no list-all endpoint in API). */
export const ADMIN_RECENT_CLIENTS_KEY = 'healthchat.admin.recentClients';

export const AdminRoutes = {
  LOGIN: '/admin/login',
  HOME: '/admin',
  CLIENTS: '/admin/clients',
  userKeys: (userId: string) => `/admin/clients/${encodeURIComponent(userId)}/keys`
} as const;
