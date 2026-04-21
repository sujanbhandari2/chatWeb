import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type {
  AdminApiKeyRow,
  AdminCreateApiKeyResult,
  AdminLoginResponse,
  AdminProfile,
  AdminTenant,
  AdminTenantDeleted
} from '../types/admin.types';

export const loginAdmin = (body: { email: string; password: string }): Promise<AdminLoginResponse> =>
  apiService.post<AdminLoginResponse>(API_PATHS.ADMIN.LOGIN, body);

export const getAdminProfile = (): Promise<AdminProfile> =>
  apiService.get<AdminProfile>(API_PATHS.ADMIN.ME);

export const listAdminTenants = (): Promise<AdminTenant[]> =>
  apiService.get<AdminTenant[]>(API_PATHS.ADMIN.TENANTS);

export const createAdminTenant = (body: {
  name: string;
  email: string;
  password: string;
}): Promise<AdminTenant> => apiService.post<AdminTenant>(API_PATHS.ADMIN.TENANTS, body);

export const updateAdminTenant = (
  id: string,
  body: { name?: string; email?: string; password?: string }
): Promise<AdminTenant> => apiService.patch<AdminTenant>(API_PATHS.ADMIN.tenant(id), body);

export const deleteAdminTenant = (id: string): Promise<AdminTenantDeleted> =>
  apiService.delete<AdminTenantDeleted>(API_PATHS.ADMIN.tenant(id));

export const listTenantApiKeys = (tenantId: string): Promise<AdminApiKeyRow[]> =>
  apiService.get<AdminApiKeyRow[]>(API_PATHS.ADMIN.tenantApiKeys(tenantId));

export const createTenantApiKey = (
  tenantId: string,
  body?: { name?: string; scopes?: string[]; expiresAt?: string }
): Promise<AdminCreateApiKeyResult> =>
  apiService.post<AdminCreateApiKeyResult>(API_PATHS.ADMIN.tenantApiKeys(tenantId), body ?? {});

export const revokeTenantApiKey = (tenantId: string, keyId: string): Promise<unknown> =>
  apiService.post<unknown>(API_PATHS.ADMIN.tenantApiKeyRevoke(tenantId, keyId), {});
