import { useEffect, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { createChatSocket } from '../lib/chat-socket';
import { isLikelyJwt } from '../utils/chat.utils';

/**
 * Vitafy chat Socket.IO:
 * - API key is required for handshake (`auth.apiKey` + `X-Api-Key` when available); sourced from `VITE_WIDGET_ACCESS_KEY` only
 * - Tenant JWT must be provided as `handshake.auth.token` (we only connect when `tenantJwt` looks like a JWT)
 *
 * This hook only manages the socket instance lifecycle. Event subscriptions live in `useChatRuntime`.
 */
export function useChatSocket(
  tenantJwt: string | undefined,
  chatUserId: string | undefined,
  enabled: boolean
): Socket | null {
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (!enabled || !tenantJwt || !chatUserId || !isLikelyJwt(tenantJwt)) {
      setSocket(null);
      return undefined;
    }

    const s = createChatSocket({ token: tenantJwt, chatUserId });

    setSocket(s);

    return () => {
      // Do not `removeAllListeners()` — `useChatRuntime` attaches handlers to this instance.
      s.disconnect();
      setSocket(null);
    };
  }, [enabled, tenantJwt, chatUserId]);

  return socket;
}
