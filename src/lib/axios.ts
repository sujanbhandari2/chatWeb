import axios from 'axios';
import { getApiBaseUrl, getResolvedApiTimeoutMs } from '../utils/runtime-endpoints.utils';
import { getResolvedApiKey, getResolvedTenantId } from './api-credentials';
import { useAdminAuthStore } from '../store/useAdminAuthStore';
import { useAuthStore } from '../store/useAuthStore';
import { ApiError } from './api-error';

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
    const apiKey = getResolvedApiKey();
    if (apiKey) {
      config.headers['X-Api-Key'] = apiKey;
    }
    const tenantId = getResolvedTenantId();
    if (tenantId) {
      config.headers['X-Tenant-Id'] = tenantId;
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
        if (isAdminArea) {
          useAdminAuthStore.getState().clearSession();
        } else if (!isAdminLoginFailure) {
          useAuthStore.getState().clearSession();
        }
      }
      return Promise.reject(ApiError.fromAxios(error));
    }
    return Promise.reject(error);
  }
);
