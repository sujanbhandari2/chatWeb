import { io, type Socket } from 'socket.io-client';
import { getChatApiKey, getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';

export type CreateChatSocketOptions = {
  /** `ChatUser.id` as numeric string (`api_doc.md`). */
  chatUserId: string;
};

/**
 * Vitafy realtime handshake:
 * - API key: `VITE_WIDGET_ACCESS_KEY` → `X-Api-Key` (non-browser) **and** `auth.apiKey` (browser-safe)
 * - Chat profile: `auth.userId` (aka `ChatUser.id`)
 */
export function createChatSocket({ chatUserId }: CreateChatSocketOptions): Socket {
  const apiKey = getChatApiKey();
  if (!apiKey) {
    throw new Error('Missing VITE_WIDGET_ACCESS_KEY for realtime connection');
  }

  // Note: browsers cannot set custom WebSocket headers; the server should read `auth.apiKey`.
  // `extraHeaders` is still useful in non-browser environments and for polling transports.
  const headers: Record<string, string> = { 'X-Api-Key': apiKey };

  return io(getResolvedSocketUrl(), {
    auth: {
      userId: chatUserId,
      apiKey,
      // Some gateways accept either spelling; harmless if ignored.
      xApiKey: apiKey
    },
    extraHeaders: headers,
    transports: ['websocket'],
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 750,
    reconnectionDelayMax: 10_000
  });
}
