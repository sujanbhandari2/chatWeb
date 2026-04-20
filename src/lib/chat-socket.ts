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
  if (!apiKey) {
    throw new Error('Missing X-Api-Key for realtime connection');
  }

  // Note: browsers cannot set custom WebSocket headers; the server should read `auth.apiKey`.
  // `extraHeaders` is still useful in non-browser environments and for polling transports.
  const headers: Record<string, string> = { 'X-Api-Key': apiKey };

  return io(getResolvedSocketUrl(), {
    auth: {
      token,
      userId: chatUserId,
      apiKey
    },
    extraHeaders: headers,
    transports: ['websocket']
  });
}
