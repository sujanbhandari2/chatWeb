import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { TenantUser } from '../types/chat';
import type { VitafyChatUserRow } from '../types/vitafy.types';
import { mapChatUserToTenantUser } from '../utils/vitafy-chat.utils';

export const getTenantUsers = (): Promise<TenantUser[]> =>
  apiService.get<VitafyChatUserRow[]>(API_PATHS.CHAT.USERS).then((rows) => rows.map(mapChatUserToTenantUser));
