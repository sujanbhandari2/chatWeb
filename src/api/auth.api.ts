import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { VitafyTenantLoginResponse } from '../types/vitafy.types';

export const loginTenant = (body: { email: string; password: string }): Promise<VitafyTenantLoginResponse> =>
  apiService.post<VitafyTenantLoginResponse>(API_PATHS.AUTH.TENANT_LOGIN, body);
