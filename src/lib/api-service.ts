import type { AxiosRequestConfig } from 'axios';
import { apiAxios } from './axios';

/** Backend `TransformInterceptor`: `{ success: true, data }` on success. */
function unwrapResponseData<T>(payload: unknown): T {
  if (
    payload &&
    typeof payload === 'object' &&
    !Array.isArray(payload) &&
    (payload as { success?: unknown }).success === true &&
    'data' in payload
  ) {
    return (payload as { data: T }).data;
  }
  return payload as T;
}

export const apiService = {
  get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.get<T>(url, config).then((res) => unwrapResponseData<T>(res.data));
  },
  post<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.post<T>(url, data, config).then((res) => unwrapResponseData<T>(res.data));
  },
  patch<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.patch<T>(url, data, config).then((res) => unwrapResponseData<T>(res.data));
  },
  delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.delete<T>(url, config).then((res) => unwrapResponseData<T>(res.data));
  }
};
