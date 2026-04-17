import { io, type Socket } from 'socket.io-client';
import { getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';
import { formatWireXApiKeyValue } from '../utils/chat-api-key.utils';

export type ChatSocketAuth = {
  token: string;
  apiKey: string;
  companyId: string;
  userId: string;
};

/** Handshake: `X-Api-Key` + JWT + `{ companyId, userId/chatUserId }` (headers + `auth` for browser WS). */
export function createChatSocket({ token, apiKey, companyId, userId }: ChatSocketAuth): Socket {
  const wireKey = formatWireXApiKeyValue(apiKey) ?? apiKey;
  return io(getResolvedSocketUrl(), {
    path: '/socket.io/',
    /**
     * Postman / Node can attach `extraHeaders` on the WebSocket upgrade; browsers often cannot.
     * Send the same material in `handshake.auth` so the server can read `X-Api-Key` equivalents
     * after upgrade. Polling still sends headers for middleware that only checks the first request.
     */
    transportOptions: {
      polling: {
        extraHeaders: {
          'X-Api-Key': wireKey,
          Authorization: `Bearer ${token}`
        }
      }
    },
    auth: {
      token,
      /** Same value as `X-Api-Key` header — many gateways read this on WS-only handshakes. */
      apiKey: wireKey,
      xApiKey: wireKey,
      companyId,
      userId,
      chatUserId: userId
    }
  });
}
