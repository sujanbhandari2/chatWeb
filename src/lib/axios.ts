import axios from 'axios';
import { getApiBaseUrl, getChatApiKey, getResolvedApiTimeoutMs } from '../utils/runtime-endpoints.utils';
import { useAdminAuthStore } from '../store/useAdminAuthStore';
import { useAuthStore } from '../store/useAuthStore';
import { ApiError } from './api-error';

export const apiAxios = axios.create({
  headers: { 'Content-Type': 'application/json' }
});

function isVitafyChatPath(url: string | undefined): boolean {
  if (!url) {
    return false;
  }
  return url.includes('/v1/chat/');
}

/** Presigned tenant uploads (`api_doc.md` — `POST /api/upload`, same `X-Api-Key` as chat). */
function isVitafyPresignedUploadPath(url: string | undefined): boolean {
  if (!url) {
    return false;
  }
  return url.includes('/upload');
}

apiAxios.interceptors.request.use((config) => {
  config.baseURL = getApiBaseUrl();
  const timeoutMs = getResolvedApiTimeoutMs();
  if (timeoutMs !== undefined) {
    config.timeout = timeoutMs;
  }

  const url = config.url ?? '';
  const method = (config.method ?? 'get').toLowerCase();
  const isChat = isVitafyChatPath(url);
  const isPresignedUpload = isVitafyPresignedUploadPath(url);
  const chatApiKeyScope = isChat || isPresignedUpload;
  const isPublicAuthPost =
    (url.includes('/v1/admin/login') || url.includes('/v1/auth/tenant/login')) && method === 'post';

  if (isPublicAuthPost) {
    delete config.headers.Authorization;
  } else if (url.includes('/v1/admin/')) {
    const adminToken = useAdminAuthStore.getState().token;
    if (adminToken) {
      config.headers.Authorization = `Bearer ${adminToken}`;
    } else {
      delete config.headers.Authorization;
    }
  } else if (url.includes('/v1/shared/')) {
    const tenantToken = useAuthStore.getState().token;
    if (tenantToken) {
      config.headers.Authorization = `Bearer ${tenantToken}`;
    } else {
      delete config.headers.Authorization;
    }
  } else if (chatApiKeyScope) {
    // Chat + presigned upload routes use X-Api-Key, not tenant JWT.
    delete config.headers.Authorization;
  } else {
    const tenantToken = useAuthStore.getState().token;
    if (tenantToken) {
      config.headers.Authorization = `Bearer ${tenantToken}`;
    } else {
      delete config.headers.Authorization;
    }
  }

  const chatKey = getChatApiKey();
  if (chatKey && chatApiKeyScope) {
    config.headers['X-Api-Key'] = chatKey;
  }
  return config;
});

apiAxios.interceptors.response.use(
  (response) => {
    const body = response.data;
    if (
      body &&
      typeof body === 'object' &&
      'success' in body &&
      (body as { success: unknown }).success === true &&
      'data' in body
    ) {
      return { ...response, data: (body as { data: unknown }).data };
    }
    return response;
  },
  (error) => {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status ?? 0;
      if (status === 401) {
        const reqUrl = error.config?.url ?? '';
        if (reqUrl.includes('/v1/admin/')) {
          useAdminAuthStore.getState().clearSession();
        } else if (reqUrl.includes('/v1/shared/') || reqUrl.includes('/v1/auth/')) {
          useAuthStore.getState().clearSession();
        } else if (!reqUrl.includes('/v1/chat/') && !reqUrl.includes('/upload')) {
          useAuthStore.getState().clearSession();
        }
      }
      return Promise.reject(ApiError.fromAxios(error));
    }
    return Promise.reject(error);
  }
);
