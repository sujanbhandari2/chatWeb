import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { chatRealtimeEvents } from '../constants/chat-realtime.constants';
import { createChatSocket } from '../lib/chat-socket';
import { conversationKeys } from '../services/conversations.service';
import type { Message } from '../types/chat';

/** Socket.IO for chat; connects with API key only; reconnects when the key changes. */
export function useChatSocket(apiKey: string): Socket | null {
  const qc = useQueryClient();
  const qcRef = useRef(qc);
  qcRef.current = qc;
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (!apiKey?.trim()) {
      setSocket(null);
      return undefined;
    }

    const s = createChatSocket(apiKey);

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
  }, [apiKey]);

  return socket;
}
