import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { VitafyChatUserRow } from '../types/vitafy.types';

export type CreateChatUserBody = {
  providerId: string;
  providerUserId: string;
  email: string;
  name?: string;
};

/** Get-or-create `ChatUser` for this tenant (requires `X-Api-Key` on `/v1/chat/*`). */
export const registerOrGetChatUser = (body: CreateChatUserBody): Promise<VitafyChatUserRow> =>
  apiService.post<VitafyChatUserRow>(API_PATHS.CHAT.USERS, body);
