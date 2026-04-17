import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { AdminClient } from '../types/admin.types';
import { parseAdminClient } from '../types/admin.types';

export type AdminLoginBody = { email: string; password: string };

export type CreateAdminClientBody = { name: string; email: string; password: string };

export type UpdateAdminClientBody = {
  name?: string;
  email?: string;
  password?: string;
};

export type CreateAdminApiKeyBody = {
  name?: string;
  scopes?: string[];
  expiresAt?: string;
};

const clientBase = (id: string) => `${API_PATHS.ADMIN.CLIENTS}/${encodeURIComponent(id)}`;

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

/** `GET {baseURL}/v1/admin/clients` → full URL `/api/v1/admin/clients` with default `VITE_API_URL` base. */
export const listAdminClients = (): Promise<AdminClient[]> =>
  apiService.get<unknown>(API_PATHS.ADMIN.CLIENTS).then((raw) => {
    const rows = unwrapAdminList(raw);
    return rows.map(parseAdminClient).filter((c): c is AdminClient => c !== null);
  });

export const createAdminClient = (body: CreateAdminClientBody): Promise<unknown> =>
  apiService.post<unknown>(API_PATHS.ADMIN.CLIENTS, body);

export const updateAdminClient = (id: string, body: UpdateAdminClientBody): Promise<unknown> =>
  apiService.patch<unknown>(clientBase(id), body);

export const deleteAdminClient = (id: string): Promise<unknown> => apiService.delete<unknown>(clientBase(id));

export const listAdminClientApiKeys = (userId: string): Promise<unknown> =>
  apiService.get<unknown>(`${clientBase(userId)}/api-keys`);

export const createAdminClientApiKey = (userId: string, body: CreateAdminApiKeyBody): Promise<unknown> =>
  apiService.post<unknown>(`${clientBase(userId)}/api-keys`, body);

export const revokeAdminClientApiKey = (userId: string, keyId: string): Promise<unknown> =>
  apiService.post<unknown>(`${clientBase(userId)}/api-keys/${encodeURIComponent(keyId)}/revoke`, {});
