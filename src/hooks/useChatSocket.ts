import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { chatRealtimeEvents } from '../constants/chat-realtime.constants';
import { createChatSocket, type ChatSocketHandshakeSession } from '../lib/chat-socket';
import { conversationKeys } from '../services/conversations.service';
import type { Message } from '../types/chat';

/** Socket.IO for chat; API key required; optional tenant JWT + chat user id for full realtime session. */
export function useChatSocket(apiKey: string, session?: ChatSocketHandshakeSession | null): Socket | null {
  const qc = useQueryClient();
  const qcRef = useRef(qc);
  qcRef.current = qc;
  const [socket, setSocket] = useState<Socket | null>(null);
  const sessionToken = session?.token ?? '';
  const sessionUserId = session?.userId ?? '';

  useEffect(() => {
    if (!apiKey?.trim()) {
      setSocket(null);
      return undefined;
    }

    const s = createChatSocket(apiKey, session);

    const onMessage = (message: Message): void => {
      const client = qcRef.current;
      void client.invalidateQueries({ queryKey: conversationKeys.messages(message.conversationId) });
      void client.invalidateQueries({ queryKey: conversationKeys.list() });
    };
    s.on(chatRealtimeEvents.message, onMessage);

    setSocket(s);

    return () => {
      s.off(chatRealtimeEvents.message, onMessage);
      s.disconnect();
      setSocket(null);
    };
  }, [apiKey, sessionToken, sessionUserId]);

  return socket;
}
