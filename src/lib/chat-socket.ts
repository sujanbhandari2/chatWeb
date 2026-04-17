import { io, type Socket } from 'socket.io-client';
import { getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';

export type ChatSocketAuth = {
  token?: string;
  apiKey?: string;
  companyId: string;
  userId: string;
};

/** Handshake `auth`: (JWT or API key) + company + chat profile id (`User.id`). */
export function createChatSocket({ token, apiKey, companyId, userId }: ChatSocketAuth): Socket {
  return io(getResolvedSocketUrl(), {
    auth: { token: token ?? '', apiKey, companyId, userId },
    transports: ['websocket']
  });
}
