import type { AxiosRequestConfig } from 'axios';
import { apiAxios } from './axios';

export const apiService = {
  get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.get<T>(url, config).then((res) => res.data as T);
  },
  post<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.post<T>(url, data, config).then((res) => res.data as T);
  },
  patch<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.patch<T>(url, data, config).then((res) => res.data as T);
  },
  delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return apiAxios.delete<T>(url, config).then((res) => res.data as T);
  }
};
