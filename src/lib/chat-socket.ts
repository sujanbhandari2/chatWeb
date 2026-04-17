import { io, type Socket } from 'socket.io-client';
import { getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';
import { formatWireXApiKeyValue } from '../utils/chat-api-key.utils';

export type ChatSocketAuth = {
  /** Client JWT when the server returns one; omit empty so `Authorization` is not sent as `Bearer `. */
  token?: string;
  apiKey: string;
  companyId: string;
  userId: string;
};

/** Handshake: `X-Api-Key` + optional JWT + `{ companyId, userId/chatUserId }` (headers + `auth` for browser WS). */
export function createChatSocket({ token, apiKey, companyId, userId }: ChatSocketAuth): Socket {
  const wireKey = formatWireXApiKeyValue(apiKey) ?? apiKey;
  const jwt = token?.trim();
  const pollingHeaders: Record<string, string> = { 'X-Api-Key': wireKey };
  if (jwt) {
    pollingHeaders.Authorization = `Bearer ${jwt}`;
  }
  return io(getResolvedSocketUrl(), {
    path: '/socket.io/',
    /**
     * Postman / Node can attach `extraHeaders` on the WebSocket upgrade; browsers often cannot.
     * Send the same material in `handshake.auth` so the server can read `X-Api-Key` equivalents
     * after upgrade. Polling still sends headers for middleware that only checks the first request.
     */
    transportOptions: {
      polling: {
        extraHeaders: pollingHeaders
      }
    },
    auth: {
      ...(jwt ? { token: jwt } : {}),
      /** Same value as `X-Api-Key` header — many gateways read this on WS-only handshakes. */
      apiKey: wireKey,
      xApiKey: wireKey,
      companyId,
      userId,
      chatUserId: userId
    }
  });
}
