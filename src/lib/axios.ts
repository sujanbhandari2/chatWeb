import axios from 'axios';
import { getApiBaseUrl, getResolvedApiTimeoutMs } from '../utils/runtime-endpoints.utils';
import { getResolvedApiKey, getResolvedCompanyId } from './api-credentials';
import { formatWireXApiKeyValue } from '../utils/chat-api-key.utils';
import { useAdminAuthStore } from '../store/useAdminAuthStore';
import { useAuthStore } from '../store/useAuthStore';
import { ApiError } from './api-error';

function readAuthorizationHeader(headers: unknown): string | undefined {
  if (!headers || typeof headers !== 'object') {
    return undefined;
  }
  const h = headers as Record<string, unknown> & { get?: (key: string) => unknown };
  if (typeof h.get === 'function') {
    const v = h.get('Authorization') ?? h.get('authorization');
    if (typeof v === 'string') {
      return v;
    }
    if (Array.isArray(v) && typeof v[0] === 'string') {
      return v[0];
    }
    return undefined;
  }
  const v = h.Authorization ?? h.authorization;
  return typeof v === 'string' ? v : undefined;
}

export const apiAxios = axios.create({
  headers: { 'Content-Type': 'application/json' }
});

apiAxios.interceptors.request.use((config) => {
  config.baseURL = getApiBaseUrl();
  const timeoutMs = getResolvedApiTimeoutMs();
  if (timeoutMs !== undefined) {
    config.timeout = timeoutMs;
  }

  const path = typeof config.url === 'string' ? config.url : '';
  const isAdminLogin = path.includes('/v1/admin/login');
  const isAdminRoute = path.includes('/v1/admin/');
  const adminToken = useAdminAuthStore.getState().token?.trim();
  const userToken = useAuthStore.getState().token?.trim();

  if (!isAdminLogin) {
    if (isAdminRoute) {
      if (adminToken) {
        config.headers.Authorization = `Bearer ${adminToken}`;
      }
    } else if (userToken) {
      config.headers.Authorization = `Bearer ${userToken}`;
    }
  }

  if (!isAdminRoute) {
    const apiKey = formatWireXApiKeyValue(getResolvedApiKey());
    if (apiKey) {
      config.headers['X-Api-Key'] = apiKey;
    }
    const companyId = getResolvedCompanyId();
    if (companyId) {
      config.headers['X-Company-Id'] = companyId;
    }
  }

  return config;
});

apiAxios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status ?? 0;
      if (status === 401) {
        const url = String(error.config?.url ?? '');
        const isAdminLoginFailure = url.includes('/v1/admin/login');
        const isAdminArea = url.includes('/v1/admin/') && !isAdminLoginFailure;
        const authHeader = readAuthorizationHeader(error.config?.headers);
        const hadBearer =
          typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ');
        if (isAdminArea) {
          useAdminAuthStore.getState().clearSession();
        } else if (!isAdminLoginFailure && hadBearer) {
          /** API-key–only chat sessions use empty Bearer; do not wipe user on 401 from key/chat alone. */
          useAuthStore.getState().clearSession();
        }
      }
      return Promise.reject(ApiError.fromAxios(error));
    }
    return Promise.reject(error);
  }
);
