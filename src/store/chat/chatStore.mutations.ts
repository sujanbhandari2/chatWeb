/**
 * Synchronous store updates: setters, merging realtime payloads into local state,
 * and UI-only flows that only call other setters (no network).
 */
import { normalizeMessage, isGroupConversation } from '../../utils/chat.utils';
import { WidgetPanelType, type MessageReaction } from '../../types/chat';
import { useAuthStore } from '../useAuthStore';
import { chatInitialState, type ChatStore } from './chatStore.types';

type SetChat = {
  (
    partial: ChatStore | Partial<ChatStore> | ((state: ChatStore) => ChatStore | Partial<ChatStore>),
    replace?: false | undefined
  ): void;
};

export function buildChatMutations(set: SetChat, get: () => ChatStore): Partial<ChatStore> {
  return {
    reset: () => set({ ...chatInitialState }),

    setConversations: (updater) =>
      set((s) => ({
        conversations: typeof updater === 'function' ? updater(s.conversations) : updater
      })),
    setTenantUsers: (updater) =>
      set((s) => ({
        tenantUsers: typeof updater === 'function' ? updater(s.tenantUsers) : updater
      })),
    setSelectedConversationId: (id) => set({ selectedConversationId: id }),
    setMessages: (updater) =>
      set((s) => ({
        messages: typeof updater === 'function' ? updater(s.messages) : updater
      })),
    setText: (text) => set({ text }),
    setError: (error) => set({ error }),
    setOpeningDirectUserId: (openingDirectUserId) => set({ openingDirectUserId }),
    setPeopleSearchQuery: (peopleSearchQuery) => set({ peopleSearchQuery }),
    setGroupTitle: (groupTitle) => set({ groupTitle }),
    setGroupSelectedUserIds: (updater) =>
      set((s) => ({
        groupSelectedUserIds: typeof updater === 'function' ? updater(s.groupSelectedUserIds) : updater
      })),
    setGroupPickerSearch: (groupPickerSearch) => set({ groupPickerSearch }),
    setCreatingGroup: (creatingGroup) => set({ creatingGroup }),
    setGroupModalError: (groupModalError) => set({ groupModalError }),
    setChatHeaderMenuOpen: (updater) =>
      set((s) => ({
        chatHeaderMenuOpen: typeof updater === 'function' ? updater(s.chatHeaderMenuOpen) : updater
      })),
    setMessageActionsMenuId: (updater) =>
      set((s) => ({
        messageActionsMenuId: typeof updater === 'function' ? updater(s.messageActionsMenuId) : updater
      })),
    setEditGroupTitle: (editGroupTitle) => set({ editGroupTitle }),
    setEditGroupParticipantIds: (updater) =>
      set((s) => ({
        editGroupParticipantIds: typeof updater === 'function' ? updater(s.editGroupParticipantIds) : updater
      })),
    setEditGroupConversationId: (editGroupConversationId) => set({ editGroupConversationId }),
    setEditGroupPickerSearch: (editGroupPickerSearch) => set({ editGroupPickerSearch }),
    setEditGroupSaving: (editGroupSaving) => set({ editGroupSaving }),
    setEditGroupError: (editGroupError) => set({ editGroupError }),
    setDeletingConversation: (deletingConversation) => set({ deletingConversation }),
    setIsRecording: (isRecording) => set({ isRecording }),
    setSocketConnected: (socketConnected) => set({ socketConnected }),
    setUnreadByConversation: (updater) =>
      set((s) => ({
        unreadByConversation: typeof updater === 'function' ? updater(s.unreadByConversation) : updater
      })),
    setWidgetRailPane: (widgetRailPane) => set({ widgetRailPane }),
    setWidgetChatSearchQuery: (widgetChatSearchQuery) => set({ widgetChatSearchQuery }),
    setWidgetInboxMenuOpen: (updater) =>
      set((s) => ({
        widgetInboxMenuOpen: typeof updater === 'function' ? updater(s.widgetInboxMenuOpen) : updater
      })),
    setRecordingDurationMs: (recordingDurationMs) => set({ recordingDurationMs }),

    patchMessageSpeechUi: (messageId, patch) =>
      set((s) => ({
        messageSpeechUi: {
          ...s.messageSpeechUi,
          [messageId]: { ...s.messageSpeechUi[messageId], ...patch }
        }
      })),

    upsertMessage: (incoming) => {
      const normalized = normalizeMessage(incoming);
      set((s) => {
        const previous = s.messages;
        const existingIndex = previous.findIndex((message) => message.id === normalized.id);
        if (existingIndex === -1) {
          return { messages: [...previous, normalized] };
        }
        const next = [...previous];
        next[existingIndex] = normalized;
        return { messages: next };
      });
    },

    bumpConversationUpdatedAt: (conversationId, iso) =>
      set((s) => ({
        conversations: s.conversations.map((c) => {
          if (c.id !== conversationId) {
            return c;
          }
          const nextT = new Date(iso).getTime();
          const curT = new Date(c.updatedAt).getTime();
          if (Number.isNaN(nextT)) {
            return c;
          }
          if (!Number.isNaN(curT) && curT > nextT) {
            return c;
          }
          return { ...c, updatedAt: iso };
        })
      })),

    updateTenantUserOnline: (userId, isOnline) =>
      set((s) => {
        const index = s.tenantUsers.findIndex((u) => u.id === userId);
        if (index === -1) {
          return s;
        }
        const current = s.tenantUsers[index];
        if (current.isOnline === isOnline) {
          return s;
        }
        const next = [...s.tenantUsers];
        next[index] = { ...current, isOnline };
        return { tenantUsers: next };
      }),

    applyTenantPresenceMap: (map) =>
      set((s) => ({
        tenantUsers: s.tenantUsers.map((u) =>
          Object.prototype.hasOwnProperty.call(map, u.id) ? { ...u, isOnline: !!map[u.id] } : u
        )
      })),

    setAllTenantOnlineFromIds: (ids) => {
      const onlineSet = new Set(ids.filter((id): id is string => typeof id === 'string'));
      set((s) => ({
        tenantUsers: s.tenantUsers.map((u) => ({ ...u, isOnline: onlineSet.has(u.id) }))
      }));
    },

    clearMessageSpeechOnConversationChange: () => set({ messageSpeechUi: {}, messageActionsMenuId: null }),

    widgetBackToInbox: () => {
      get().setChatHeaderMenuOpen(false);
      get().setMessageActionsMenuId(null);
      get().setWidgetInboxMenuOpen(false);
      get().setWidgetRailPane(WidgetPanelType.CHATS);
      get().setSelectedConversationId('');
      get().setMessages([]);
    },

    openGroupModal: () => {
      get().setGroupModalError('');
      get().setGroupTitle('');
      get().setGroupSelectedUserIds([]);
      get().setGroupPickerSearch('');
      get().setWidgetRailPane(WidgetPanelType.NEW_GROUP);
    },

    exitNewGroupRailToChats: () => {
      if (get().creatingGroup) {
        return;
      }
      get().setWidgetRailPane(WidgetPanelType.CHATS);
      get().setGroupModalError('');
    },

    exitEditGroupRailToChats: () => {
      if (get().editGroupSaving) {
        return;
      }
      get().setWidgetRailPane(WidgetPanelType.CHATS);
      get().setEditGroupError('');
    },

    addUserToGroupSelection: (userId) =>
      get().setGroupSelectedUserIds((previous) => (previous.includes(userId) ? previous : [...previous, userId])),

    removeUserFromGroupSelection: (userId) =>
      get().setGroupSelectedUserIds((previous) => previous.filter((id) => id !== userId)),

    addEditGroupMember: (userId) =>
      get().setEditGroupParticipantIds((previous) => (previous.includes(userId) ? previous : [...previous, userId])),

    removeEditGroupMember: (userId) => {
      const user = useAuthStore.getState().user;
      if (userId === user?.id) {
        return;
      }
      get().setEditGroupParticipantIds((previous) => {
        if (previous.length <= 2) {
          return previous;
        }
        return previous.filter((id) => id !== userId);
      });
    },

    openEditGroupModal: () => {
      const user = useAuthStore.getState().user;
      const { conversations, selectedConversationId } = get();
      const selectedConversation =
        conversations.find((conversation) => conversation.id === selectedConversationId) ?? null;
      if (!selectedConversation || !isGroupConversation(selectedConversation)) {
        return;
      }
      get().setEditGroupError('');
      get().setEditGroupConversationId(selectedConversation.id);
      get().setEditGroupTitle(selectedConversation.title?.trim() ?? '');
      const ids = selectedConversation.participants.map((p) => p.userId);
      get().setEditGroupParticipantIds([...ids]);
      set({ editGroupInitialParticipantIds: [...ids] });
      get().setEditGroupPickerSearch('');
      get().setWidgetRailPane(WidgetPanelType.EDIT_GROUP);
      get().setChatHeaderMenuOpen(false);
    },

    applyReactionFromSocket: (reaction) => {
      const selectedConversationId = get().selectedConversationId;
      get().setMessages((previous) => {
        const convId = reaction.conversationId;
        if (convId && convId !== selectedConversationId) {
          return previous;
        }
        if (!previous.some((m) => m.id === reaction.messageId)) {
          return previous;
        }

        const normalized: MessageReaction = {
          id: reaction.id ?? `evt:${reaction.messageId}:${reaction.userId}:${Date.now()}`,
          messageId: reaction.messageId,
          userId: reaction.userId,
          emoji: reaction.emoji ?? reaction.reactionType ?? '👍',
          createdAt: reaction.createdAt ?? new Date().toISOString(),
          user:
            reaction.user ??
            ({
              id: reaction.userId,
              name: null,
              email: '…',
              avatarUrl: null,
              status: null
            } satisfies import('../../types/chat').PublicUser)
        };

        return previous.map((msg) => {
          if (msg.id !== normalized.messageId) {
            return msg;
          }
          const list = msg.reactions ?? [];
          const filtered = list.filter((item) => item.userId !== normalized.userId);
          return { ...msg, reactions: [...filtered, normalized] };
        });
      });
    },

    applyMessageDeleted: (payload) => {
      if (payload.conversationId !== get().selectedConversationId) {
        return;
      }
      get().setMessages((previous) =>
        previous.map((message) =>
          message.id === payload.messageId
            ? {
                ...message,
                deletedAt: payload.deletedAt,
                content: '[deleted]'
              }
            : message
        )
      );
    },

    applyDeliveredReceipt: (receipt) => {
      get().setMessages((previous) =>
        previous.map((message) => {
          if (message.id !== receipt.messageId) {
            return message;
          }
          const filtered = (message.deliveredReceipts ?? []).filter((item) => item.userId !== receipt.userId);
          return { ...message, deliveredReceipts: [...filtered, receipt] };
        })
      );
    },

    clearRemoteTypingPeers: () => set({ remoteTypingUserIds: [] }),

    applyRemoteTypingStart: (conversationId, userId, currentUserId) => {
      if (!userId || userId === currentUserId) {
        return;
      }
      if (conversationId !== get().selectedConversationId) {
        return;
      }
      set((s) => {
        if (s.remoteTypingUserIds.includes(userId)) {
          return s;
        }
        return { remoteTypingUserIds: [...s.remoteTypingUserIds, userId] };
      });
    },

    applyRemoteTypingStop: (conversationId, userId) => {
      if (conversationId !== get().selectedConversationId) {
        return;
      }
      set((s) => ({
        remoteTypingUserIds: s.remoteTypingUserIds.filter((id) => id !== userId)
      }));
    },

    applyReadReceipt: (receipt) => {
      get().setMessages((previous) =>
        previous.map((message) => {
          if (message.id !== receipt.messageId) {
            return message;
          }
          const filtered = (message.readReceipts ?? []).filter((item) => item.userId !== receipt.userId);
          return { ...message, readReceipts: [...filtered, receipt] };
        })
      );
    }
  };
}
