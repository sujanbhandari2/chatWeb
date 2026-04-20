import { io, type Socket } from 'socket.io-client';
import { getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';
import { formatWireXApiKeyValue } from '../utils/chat-api-key.utils';

/** Tenant JWT + `ChatUser.id` for full session (tenant room, `join_conversation`, etc.). Omit for API-key-only connect. */
export type ChatSocketHandshakeSession = {
  token: string;
  /** `ChatUser.id` as numeric string; server also accepts `chatUserId` in `auth`. */
  userId: string;
};

/** Handshake: `X-Api-Key` (+ optional `Authorization`) and mirrored values in `auth` for WS upgrades. */
export function createChatSocket(apiKey: string, session?: ChatSocketHandshakeSession | null): Socket {
  const wireKey = formatWireXApiKeyValue(apiKey) ?? apiKey;
  const pollingHeaders: Record<string, string> = { 'X-Api-Key': wireKey };
  const token = session?.token?.trim();
  const userId = session?.userId?.trim();
  if (token) {
    pollingHeaders.Authorization = `Bearer ${token}`;
  }

  const auth: Record<string, string> = {
    apiKey: wireKey,
    xApiKey: wireKey
  };
  if (token) {
    auth.token = token;
  }
  if (userId) {
    auth.userId = userId;
    auth.chatUserId = userId;
  }

  return io(getResolvedSocketUrl(), {
    path: '/socket.io/',
    /** In dev, avoid infinite reconnect spam when nothing speaks Engine.IO on `VITE_SOCKET_URL` / API origin. */
    ...(import.meta.env.DEV
      ? { reconnectionAttempts: 12, reconnectionDelay: 1500, reconnectionDelayMax: 8000 }
      : {}),
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
    auth
  });
}
