import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { createChatSocket, type ChatSocketAuth } from '../lib/chat-socket';
import { conversationKeys } from '../services/conversations.service';
import type { Message } from '../types/chat';

/** Socket.IO for chat; disconnects when auth context changes. */
export function useChatSocket(auth: ChatSocketAuth | null): Socket | null {
  const qc = useQueryClient();
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (!auth?.apiKey?.trim() || !auth.companyId?.trim() || !auth.userId?.trim()) {
      setSocket(null);
      return undefined;
    }

    const s = createChatSocket(auth);

    const onMessage = (message: Message): void => {
      void qc.invalidateQueries({ queryKey: conversationKeys.messages(message.conversationId) });
      void qc.invalidateQueries({ queryKey: conversationKeys.list() });
    };
    s.on('message', onMessage);

    setSocket(s);

    return () => {
      s.off('message', onMessage);
      s.removeAllListeners();
      s.disconnect();
      setSocket(null);
    };
  }, [auth?.token, auth?.apiKey, auth?.companyId, auth?.userId, qc]);

  return socket;
}
