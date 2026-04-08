import { create } from 'zustand';
import { buildChatMutations } from './chat/chatStore.mutations';
import { buildChatRemote } from './chat/chatStore.remote';
import { chatInitialState, type ChatStore, type MessageSpeechUiState, type WidgetRailPane } from './chat/chatStore.types';

export type { MessageSpeechUiState, WidgetRailPane };

export const useChatStore = create<ChatStore>((set, get) => {
  const store: ChatStore = {
    ...chatInitialState,
    ...buildChatMutations(set, get),
    ...buildChatRemote(set, get)
  } as ChatStore;
  return store;
});
