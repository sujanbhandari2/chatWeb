import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { createChatSocket } from '../lib/chat-socket';
import { conversationKeys } from '../services/conversations.service';
import type { Message } from '../types/chat';

/** Socket.IO for Vitafy chat: tenant JWT + `ChatUser.id` + optional `X-Api-Key` / `auth.apiKey`. */
export function useChatSocket(
  token: string | undefined,
  chatUserId: string | undefined
): Socket | null {
  const qc = useQueryClient();
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (!token || !chatUserId) {
      setSocket(null);
      return undefined;
    }

    const s = createChatSocket({ token, chatUserId });

    const onMessage = (message: Message): void => {
      void qc.invalidateQueries({ queryKey: conversationKeys.messages(message.conversationId) });
      void qc.invalidateQueries({ queryKey: conversationKeys.list() });
    };
    s.on('message_received', onMessage);
    s.on('message', onMessage);

    setSocket(s);

    return () => {
      s.off('message_received', onMessage);
      s.off('message', onMessage);
      s.removeAllListeners();
      s.disconnect();
      setSocket(null);
    };
  }, [token, chatUserId, qc]);

  return socket;
}
