import { useShallow } from 'zustand/react/shallow';
import { useChatStore } from '../store/useChatStore';
import type { ChatStore } from '../store/chat/chatStore.types';

/** Multi-field chat subscriptions with shallow equality (Zustand idiom without repeating `useShallow`). */
export function useChatSelectors<T>(selector: (state: ChatStore) => T): T {
  return useChatStore(useShallow(selector));
}
