import { createContext, useContext, type ReactNode } from 'react';
import type { ChatRuntimeValue } from '../types/chat-runtime.types';

export type { ChatRuntimeValue } from '../types/chat-runtime.types';

const ChatRuntimeContext = createContext<ChatRuntimeValue | null>(null);

export function ChatRuntimeProvider({
  value,
  children
}: {
  value: ChatRuntimeValue;
  children: ReactNode;
}): JSX.Element {
  return <ChatRuntimeContext.Provider value={value}>{children}</ChatRuntimeContext.Provider>;
}

export function useChatRuntimeContext(): ChatRuntimeValue {
  const ctx = useContext(ChatRuntimeContext);
  if (!ctx) {
    throw new Error('useChatRuntimeContext must be used within ChatRuntimeProvider');
  }
  return ctx;
}
