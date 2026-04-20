import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { AdminTenant } from '../types/admin.types';
import { parseAdminTenant } from '../types/admin.types';

export type AdminLoginBody = { email: string; password: string };

export type CreateAdminTenantBody = { name: string; email: string; password: string };

export type UpdateAdminTenantBody = {
  name?: string;
  email?: string;
  password?: string;
};

export type CreateAdminApiKeyBody = {
  name?: string;
  scopes?: string[];
  expiresAt?: string;
};

const tenantBase = (id: string) => `${API_PATHS.ADMIN.TENANTS}/${encodeURIComponent(id)}`;

function unwrapAdminList(raw: unknown): unknown[] {
  if (Array.isArray(raw)) {
    return raw;
  }
  if (raw && typeof raw === 'object') {
    const r = raw as Record<string, unknown>;
    if (Array.isArray(r.data)) {
      return r.data as unknown[];
    }
    if (Array.isArray(r.items)) {
      return r.items as unknown[];
    }
  }
  return [];
}

export const loginAdmin = (body: AdminLoginBody): Promise<unknown> =>
  apiService.post<unknown>(API_PATHS.ADMIN.LOGIN, body);

export const getAdminProfile = (): Promise<unknown> => apiService.get<unknown>(API_PATHS.ADMIN.ME);

/** `GET {baseURL}/v1/admin/tenants` → `/api/v1/admin/tenants` with default `VITE_API_URL` base (`…/api`). */
export const listAdminTenants = (): Promise<AdminTenant[]> =>
  apiService.get<unknown>(API_PATHS.ADMIN.TENANTS).then((raw) => {
    const rows = unwrapAdminList(raw);
    return rows.map(parseAdminTenant).filter((c): c is AdminTenant => c !== null);
  });

export const createAdminTenant = (body: CreateAdminTenantBody): Promise<unknown> =>
  apiService.post<unknown>(API_PATHS.ADMIN.TENANTS, body);

export const updateAdminTenant = (id: string, body: UpdateAdminTenantBody): Promise<unknown> =>
  apiService.patch<unknown>(tenantBase(id), body);

export const deleteAdminTenant = (id: string): Promise<unknown> => apiService.delete<unknown>(tenantBase(id));

export const listAdminTenantApiKeys = (userId: string): Promise<unknown> =>
  apiService.get<unknown>(`${tenantBase(userId)}/api-keys`);

export const createAdminTenantApiKey = (userId: string, body: CreateAdminApiKeyBody): Promise<unknown> =>
  apiService.post<unknown>(`${tenantBase(userId)}/api-keys`, body);

export const revokeAdminTenantApiKey = (userId: string, keyId: string): Promise<unknown> =>
  apiService.post<unknown>(`${tenantBase(userId)}/api-keys/${encodeURIComponent(keyId)}/revoke`, {});
