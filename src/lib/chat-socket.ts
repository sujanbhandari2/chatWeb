import { io, type Socket } from 'socket.io-client';
import { getChatApiKey, getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';

export type CreateChatSocketOptions = {
  /** Tenant JWT (`typ: "tenant"`). Must be sent as `handshake.auth.token` (not `Authorization` on WS). */
  token: string;
  /** `ChatUser.id` as numeric string (`api_doc.md`). */
  chatUserId: string;
};

/**
 * Vitafy realtime handshake (see `api_doc.md` / updated socket docs):
 * - API key: `VITE_WIDGET_ACCESS_KEY` → `X-Api-Key` header (non-browser / tooling) **and** `auth.apiKey` mirror (browser-safe)
 * - Tenant JWT: `auth.token` only
 * - Chat profile: `auth.userId` (aka `ChatUser.id`)
 */
export function createChatSocket({ token, chatUserId }: CreateChatSocketOptions): Socket {
  const apiKey = getChatApiKey();
  if (!apiKey) {
    throw new Error('Missing VITE_WIDGET_ACCESS_KEY for realtime connection');
  }

  // Note: browsers cannot set custom WebSocket headers; the server should read `auth.apiKey`.
  // `extraHeaders` is still useful in non-browser environments and for polling transports.
  const headers: Record<string, string> = { 'X-Api-Key': apiKey };

  return io(getResolvedSocketUrl(), {
    auth: {
      token,
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
