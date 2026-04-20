import { io, type Socket } from 'socket.io-client';
import { getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';
import { formatWireXApiKeyValue } from '../utils/chat-api-key.utils';

/** Handshake: `X-Api-Key` and the same value in `auth` (for WS upgrades where browsers omit `extraHeaders`). No JWT. */
export function createChatSocket(apiKey: string): Socket {
  const wireKey = formatWireXApiKeyValue(apiKey) ?? apiKey;
  const pollingHeaders: Record<string, string> = { 'X-Api-Key': wireKey };
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
    auth: {
      /** Same value as `X-Api-Key` header — many gateways read this on WS-only handshakes. */
      apiKey: wireKey,
      xApiKey: wireKey
    }
  });
}
