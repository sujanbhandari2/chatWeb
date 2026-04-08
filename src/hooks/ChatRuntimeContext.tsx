import { createContext, useContext, type ReactNode, type RefObject } from 'react';

/** Refs and recording controls shared by chat UI (sidebar, thread, group forms). */
export type ChatRuntimeValue = {
  messageScrollerRef: RefObject<HTMLElement | null>;
  chatHeaderMenuRef: RefObject<HTMLDivElement | null>;
  /** ⋮ overflow next to the conversation list search */
  chatsListOverflowMenuRef: RefObject<HTMLDivElement | null>;
  newGroupFormId: string;
  editGroupFormId: string;
  startRecording: () => Promise<void>;
  finishRecording: () => void;
  cancelRecording: () => void;
};

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
