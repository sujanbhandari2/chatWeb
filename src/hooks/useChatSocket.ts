import { useEffect, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { createChatSocket } from '../lib/chat-socket';
import { getChatApiKey } from '../utils/runtime-endpoints.utils';

/**
 * Vitafy chat Socket.IO:
 * - Handshake uses `VITE_WIDGET_ACCESS_KEY` (`auth.apiKey` / `X-Api-Key`) and `auth.userId` (chat user id).
 * - Tenant JWT is not used for realtime; admin JWT is only for `/admin` REST, not this socket.
 *
 * This hook only manages the socket instance lifecycle. Event subscriptions live in `useChatRuntime`.
 */
export function useChatSocket(chatUserId: string | undefined, enabled: boolean): Socket | null {
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (!enabled || !chatUserId || !getChatApiKey()) {
      setSocket(null);
      return undefined;
    }

    const s = createChatSocket({ chatUserId });

    setSocket(s);

    return () => {
      // Do not `removeAllListeners()` — `useChatRuntime` attaches handlers to this instance.
      s.disconnect();
      setSocket(null);
    };
  }, [enabled, chatUserId]);

  return socket;
}
