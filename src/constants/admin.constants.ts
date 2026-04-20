/** Admin console (react-router) — separate from widget embed. */
export const ADMIN_SESSION_STORAGE_KEY = 'healthchat.admin.session';

/** Session-scoped cache of tenants (mirrors server list when `GET /v1/admin/tenants` succeeds). */
export const ADMIN_RECENT_TENANTS_KEY = 'healthchat.admin.recentTenants';

export const AdminRoutes = {
  LOGIN: '/admin/login',
  HOME: '/admin',
  TENANTS: '/admin/tenants',
  userKeys: (userId: string) => `/admin/tenants/${encodeURIComponent(userId)}/keys`
} as const;
