import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { createChatSocket } from '../lib/chat-socket';
import { conversationKeys } from '../services/conversations.service';
import type { Message } from '../types/chat';

/** Creates a single Socket.IO connection for the auth token; disconnects on token change/unmount. */
export function useChatSocket(token: string | undefined): Socket | null {
  const qc = useQueryClient();
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (!token) {
      setSocket(null);
      return undefined;
    }

    const s = createChatSocket(token);

    const onMessageReceived = (message: Message): void => {
      void qc.invalidateQueries({ queryKey: conversationKeys.messages(message.conversationId) });
      void qc.invalidateQueries({ queryKey: conversationKeys.list() });
    };
    s.on('message_received', onMessageReceived);

    setSocket(s);

    return () => {
      s.off('message_received', onMessageReceived);
      s.removeAllListeners();
      s.disconnect();
      setSocket(null);
    };
  }, [token, qc]);

  return socket;
}
