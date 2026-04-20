import axios from 'axios';
import { getApiBaseUrl, getChatApiKey, getResolvedApiTimeoutMs } from '../utils/runtime-endpoints.utils';
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

apiAxios.interceptors.request.use((config) => {
  config.baseURL = getApiBaseUrl();
  const timeoutMs = getResolvedApiTimeoutMs();
  if (timeoutMs !== undefined) {
    config.timeout = timeoutMs;
  }
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  const chatKey = getChatApiKey();
  if (chatKey && isVitafyChatPath(config.url)) {
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
        useAuthStore.getState().clearSession();
      }
      return Promise.reject(ApiError.fromAxios(error));
    }
    return Promise.reject(error);
  }
);
