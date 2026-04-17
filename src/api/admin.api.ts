import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';

export type AdminLoginBody = { email: string; password: string };

export type CreateAdminClientBody = { name: string; email: string; password: string };

export type CreateAdminApiKeyBody = {
  name?: string;
  scopes?: string[];
  expiresAt?: string;
};

const clientBase = (id: string) => `${API_PATHS.ADMIN.CLIENTS}/${encodeURIComponent(id)}`;

export const loginAdmin = (body: AdminLoginBody): Promise<unknown> =>
  apiService.post<unknown>(API_PATHS.ADMIN.LOGIN, body);

export const getAdminProfile = (): Promise<unknown> => apiService.get<unknown>(API_PATHS.ADMIN.ME);

export const createAdminClient = (body: CreateAdminClientBody): Promise<unknown> =>
  apiService.post<unknown>(API_PATHS.ADMIN.CLIENTS, body);

export const deleteAdminClient = (id: string): Promise<unknown> => apiService.delete<unknown>(clientBase(id));

export const listAdminClientApiKeys = (userId: string): Promise<unknown> =>
  apiService.get<unknown>(`${clientBase(userId)}/api-keys`);

export const createAdminClientApiKey = (userId: string, body: CreateAdminApiKeyBody): Promise<unknown> =>
  apiService.post<unknown>(`${clientBase(userId)}/api-keys`, body);

export const revokeAdminClientApiKey = (userId: string, keyId: string): Promise<unknown> =>
  apiService.post<unknown>(`${clientBase(userId)}/api-keys/${encodeURIComponent(keyId)}/revoke`, {});
