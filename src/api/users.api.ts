import { API_PATHS } from '../constants/api.constants';
import { apiService } from '../lib/api-service';
import type { TenantUser } from '../types/chat';

export const getTenantUsers = (): Promise<TenantUser[]> =>
  apiService.get<{ data: TenantUser[] }>(API_PATHS.USERS).then((r) => r.data);
