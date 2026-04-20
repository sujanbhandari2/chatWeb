import { io, type Socket } from 'socket.io-client';
import { getChatApiKey, getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';

export type CreateChatSocketOptions = {
  token: string;
  /** `ChatUser.id` as numeric string (`api_doc.md`). */
  chatUserId: string;
};

/**
 * Vitafy realtime: API key (required) + tenant JWT + chat profile id (`api_doc.md` quick UI flow).
 */
export function createChatSocket({ token, chatUserId }: CreateChatSocketOptions): Socket {
  const apiKey = getChatApiKey();
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`
  };
  if (apiKey) {
    headers['X-Api-Key'] = apiKey;
  }

  return io(getResolvedSocketUrl(), {
    auth: {
      token,
      userId: chatUserId,
      ...(apiKey ? { apiKey } : {})
    },
    extraHeaders: headers,
    transports: ['websocket']
  });
}
