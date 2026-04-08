import axios from 'axios';
import { getApiBaseUrl, getResolvedApiTimeoutMs } from '../utils/runtime-endpoints.utils';
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
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiAxios.interceptors.response.use(
  (response) => response,
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
