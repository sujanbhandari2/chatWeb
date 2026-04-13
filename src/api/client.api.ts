import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { CreateAccountResponse } from '../types/chat';

export type ClientLoginBody = { email: string; password: string };

/** Client portal JWT (separate from widget chat-user bootstrap). */
export const loginClientUser = (body: ClientLoginBody): Promise<CreateAccountResponse> =>
  apiService.post<CreateAccountResponse>(API_PATHS.CLIENT.LOGIN, body);

export const getSystemHealth = (): Promise<unknown> =>
  apiService.get<unknown>(API_PATHS.CLIENT.HEALTH);
