import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { CreateAccountResponse } from '../types/chat';

export type TenantLoginBody = { email: string; password: string };

/** Tenant portal JWT (separate from widget chat-user bootstrap). */
export const loginTenantUser = (body: TenantLoginBody): Promise<CreateAccountResponse> =>
  apiService.post<CreateAccountResponse>(API_PATHS.TENANT.LOGIN, body);

export const getSystemHealth = (): Promise<unknown> =>
  apiService.get<unknown>(API_PATHS.TENANT.HEALTH);
