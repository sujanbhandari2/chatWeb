/**
 * Actions that talk to the backend: REST, uploads, socket acks, and chat AI routes.
 */
import type { FormEvent } from 'react';
import * as conversationsApi from '../../api/conversations.api';
import { getTenantUsers } from '../../api/users.api';
import { uploadFileRequest } from '../../api/upload.api';
import { getChatApiKey } from '../../utils/runtime-endpoints.utils';
import { isGlobalConversation, isLikelyJwt, normalizeMessage } from '../../utils/chat.utils';
import { WidgetPanelType, type Message, type MessageReaction, type MessageType } from '../../types/chat';
import { SELECTED_CONVERSATION_STORAGE_KEY } from '../../constants/session.constants';
import { CLIENT_GOING_OFFLINE_EVENT } from '../../features/chat/chat.constants';
import { chatEmitWithAck, getChatSocket } from '../../utils/chat-socket-bridge';
import { useAuthStore } from '../useAuthStore';
import type { ChatStore } from './chatStore.types';
import { findDirectConversation } from './chatStore.utils';
import type { TenantUser } from '../../types/chat';
function isWidgetLikeSessionToken(token: string): boolean {
  // Widget embed can use a non-JWT session marker while still using API-key chat REST.
  return Boolean(token) && !isLikelyJwt(token);
}

type SetChat = {
  (
    partial: ChatStore | Partial<ChatStore> | ((state: ChatStore) => ChatStore | Partial<ChatStore>),
    replace?: false | undefined
  ): void;
};

export function buildChatRemote(_set: SetChat, get: () => ChatStore): Partial<ChatStore> {
  return {
    handleLogout: () => {
      const socket = getChatSocket();
      const user = useAuthStore.getState().user;
      if (socket?.connected && user?.id) {
        socket.emit(CLIENT_GOING_OFFLINE_EVENT, { userId: user.id, reason: 'logout' });
      }
      useAuthStore.getState().clearSession();
      get().reset();
      window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
    },

    selectConversation: async (conversationId) => {
      const token = useAuthStore.getState().token;
      if (!token) {
        return;
      }
      const previousConversationId = get().selectedConversationId;
      get().setError('');
      get().setSelectedConversationId(conversationId);
      if (conversationId !== previousConversationId) {
        get().setMessages([]);
      }
      get().setUnreadByConversation((previous) => {
        if (!previous[conversationId]) {
          return previous;
        }
        const next = { ...previous };
        delete next[conversationId];
        return next;
      });
      try {
        const messagesPage = await conversationsApi.getMessagesPage(conversationId);
        get().setMessages(messagesPage.data.map(normalizeMessage));
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to load conversation');
      }
    },

    refreshConversations: async () => {
      const user = useAuthStore.getState().user;
      if (!user) {
        get().setConversations([]);
        return [];
      }
      const data = await conversationsApi.listConversations(user.id);
      get().setConversations(data);
      return data;
    },

    refreshUsers: async () => {
      const data = await getTenantUsers();
      const me = useAuthStore.getState().user;
      const selfId = (me?.id ?? '').trim();
      const selfEmail = (me?.email ?? '').trim().toLowerCase();
      const withoutSelf = data.filter((u: TenantUser) => {
        if (selfId && String(u.id).trim() === selfId) {
          return false;
        }
        if (selfEmail && u.email.trim().toLowerCase() === selfEmail) {
          return false;
        }
        return true;
      });
      get().setTenantUsers(withoutSelf);
    },

    bootstrapChatApp: async () => {
      const token = useAuthStore.getState().token;
      const [loadedConversations] = await Promise.all([get().refreshConversations(), get().refreshUsers()]);
      // Widget-only chat session (no tenant JWT): start on People so the user picks who to chat with first.
      const isWidgetLikeSession = isWidgetLikeSessionToken(token);
      if (isWidgetLikeSession) {
        get().setWidgetRailPane(WidgetPanelType.PEOPLE);
        get().setSelectedConversationId('');
        get().setMessages([]);
        return;
      }

      const persistedConversationId = window.localStorage.getItem(SELECTED_CONVERSATION_STORAGE_KEY);
      const hasPersistedConversation =
        !!persistedConversationId &&
        loadedConversations.some((conversation) => conversation.id === persistedConversationId);
      const globalConversation = loadedConversations.find((conversation) => isGlobalConversation(conversation));
      const initialConversationId =
        (hasPersistedConversation ? persistedConversationId : undefined) ??
        globalConversation?.id ??
        loadedConversations[0]?.id;

      if (initialConversationId) {
        get().setSelectedConversationId(initialConversationId);
        get().setUnreadByConversation((previous) => {
          if (!previous[initialConversationId]) {
            return previous;
          }
          const next = { ...previous };
          delete next[initialConversationId];
          return next;
        });
        const messagesPage = await conversationsApi.getMessagesPage(initialConversationId);
        get().setMessages(messagesPage.data.map(normalizeMessage));
      }
    },

    openDirectChat: async (target) => {
      const token = useAuthStore.getState().token;
      const user = useAuthStore.getState().user;
      if (!token || !user) {
        return;
      }
      get().setError('');
      get().setOpeningDirectUserId(target.id);
      try {
        const existing = findDirectConversation(get().conversations, user.id, target.id);
        if (existing) {
          get().setWidgetRailPane(WidgetPanelType.CHATS);
          await get().selectConversation(existing.id);
          return;
        }
        const createdConversation = await conversationsApi.createDirectConversation(user.id, target.id);
        await get().refreshConversations();
        get().setWidgetRailPane(WidgetPanelType.CHATS);
        await get().selectConversation(createdConversation.id);
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to open direct chat');
      } finally {
        get().setOpeningDirectUserId('');
      }
    },

    handleCreateGroup: async (event: FormEvent) => {
      event.preventDefault();
      const token = useAuthStore.getState().token;
      const user = useAuthStore.getState().user;
      if (!token || !user) {
        return;
      }
      const { groupTitle, groupSelectedUserIds } = get();
      const title = groupTitle.trim();
      if (title.length < 1 || title.length > 120) {
        get().setGroupModalError('Group name must be 1–120 characters.');
        return;
      }
      if (groupSelectedUserIds.length < 2) {
        get().setGroupModalError('Add at least two other people to the group.');
        return;
      }
      get().setCreatingGroup(true);
      get().setGroupModalError('');
      try {
        const participantIds = [...new Set([user.id, ...groupSelectedUserIds])];
        const created = await conversationsApi.createGroupConversation(title, user.id, participantIds);
        get().setWidgetRailPane(WidgetPanelType.CHATS);
        get().setGroupTitle('');
        get().setGroupSelectedUserIds([]);
        get().setGroupPickerSearch('');
        await get().refreshConversations();
        await get().selectConversation(created.id);
      } catch (err) {
        get().setGroupModalError(err instanceof Error ? err.message : 'Could not create group');
      } finally {
        get().setCreatingGroup(false);
      }
    },

    handleSaveEditGroup: async (event: FormEvent) => {
      event.preventDefault();
      const token = useAuthStore.getState().token;
      const user = useAuthStore.getState().user;
      if (!token || !user) {
        return;
      }
      const {
        editGroupConversationId: convId,
        editGroupParticipantIds,
        editGroupInitialParticipantIds: initialIds
      } = get();
      const initial = new Set(initialIds);
      const current = new Set(editGroupParticipantIds);
      const removedSelf = initial.has(user.id) && !current.has(user.id);

      if (!removedSelf && editGroupParticipantIds.length < 2) {
        get().setEditGroupError('A group needs at least two members.');
        return;
      }

      get().setEditGroupSaving(true);
      get().setEditGroupError('');

      try {
        const selectedConversation =
          get().conversations.find((conversation) => conversation.id === convId) ?? null;
        const convType = selectedConversation?.type ?? 'GROUP';

        const added = [...current].filter((id) => !initial.has(id));
        const removed = [...initial].filter((id) => !current.has(id));
        const removedOthers = removed.filter((id) => id !== user.id);

        if (removedOthers.length > 0 || removedSelf) {
          get().setEditGroupError('Removing members is not supported on this server.');
          return;
        }

        if (added.length > 0) {
          await conversationsApi.addConversationParticipants(convId, added, {
            actorUserId: user.id,
            conversationType: convType
          });
        }

        get().setWidgetRailPane(WidgetPanelType.CHATS);
        await get().refreshConversations();
        await get().selectConversation(convId);
      } catch (err) {
        get().setEditGroupError(err instanceof Error ? err.message : 'Failed to update group');
      } finally {
        get().setEditGroupSaving(false);
      }
    },

    handleLeaveGroup: async () => {
      const token = useAuthStore.getState().token;
      const user = useAuthStore.getState().user;
      if (!token || !user) {
        return;
      }
      const convId = get().editGroupConversationId;
      if (!convId) {
        return;
      }
      if (!window.confirm('Leave this group? You will need a new invite to rejoin.')) {
        return;
      }
      get().setEditGroupSaving(true);
      get().setEditGroupError('');
      try {
        get().setEditGroupError('Leaving a group is not supported on this server.');
      } catch (err) {
        get().setEditGroupError(err instanceof Error ? err.message : 'Could not leave group');
      } finally {
        get().setEditGroupSaving(false);
      }
    },

    handleDeleteSelectedConversation: async () => {
      get().setChatHeaderMenuOpen(false);
      get().setError('Deleting conversations is not supported by the Vitafy chat API.');
    },

    handleSendText: async () => {
      const { selectedConversationId, text } = get();
      if (!selectedConversationId || !text.trim()) {
        return;
      }
      try {
        const token = useAuthStore.getState().token;
        const user = useAuthStore.getState().user;
        const trimmed = text.trim();

        let message: Message;
        if (isWidgetLikeSessionToken(token)) {
          if (!user?.id) {
            throw new Error('Missing chat user');
          }
          message = await conversationsApi.postConversationRestMessage(selectedConversationId, {
            type: 'TEXT',
            content: trimmed,
            senderId: user.id
          });
        } else {
          message = await chatEmitWithAck<Message>('send_message', {
            conversationId: selectedConversationId,
            type: 'TEXT' as MessageType,
            content: trimmed
          });
        }
        get().upsertMessage(message);
        get().bumpConversationUpdatedAt(selectedConversationId, message.createdAt);
        get().setText('');
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to send message');
      }
    },

    handleSendUploadedMessage: async (file, type) => {
      const token = useAuthStore.getState().token;
      const user = useAuthStore.getState().user;
      const { selectedConversationId } = get();
      if (!token || !selectedConversationId) {
        return;
      }
      if (!user?.id) {
        get().setError('Missing chat user');
        return;
      }
      if (!getChatApiKey()) {
        get().setError(
          'Chat API key is required to upload files (set VITE_WIDGET_ACCESS_KEY for presigned storage).'
        );
        return;
      }
      try {
        const uploaded = await uploadFileRequest(file);
        const message = await conversationsApi.postConversationRestMessage(selectedConversationId, {
          type,
          senderId: user.id,
          attachments: [
            {
              url: uploaded.fileUrl,
              mimeType: file.type || uploaded.mimeType || undefined,
              fileName: file.name || undefined,
              byteSize: uploaded.byteSize,
              kind: 'upload'
            }
          ]
        });
        get().upsertMessage(message);
        get().bumpConversationUpdatedAt(selectedConversationId, message.createdAt);
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Upload failed');
      }
    },

    handleReact: (messageId, emoji) => {
      const user = useAuthStore.getState().user;
      const token = useAuthStore.getState().token;
      const { selectedConversationId } = get();
      if (!user || !selectedConversationId) {
        return;
      }

      get().setError('');
      get().setMessageActionsMenuId(null);
      const conversationId = selectedConversationId;
      const optimisticId = `optimistic:${messageId}:${user.id}:${emoji}`;
      const optimisticReaction: MessageReaction = {
        id: optimisticId,
        messageId,
        userId: user.id,
        emoji,
        createdAt: new Date().toISOString(),
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          avatarUrl: null,
          status: user.status
        }
      };

      get().setMessages((previous) =>
        previous.map((m) => {
          if (m.id !== messageId) {
            return m;
          }
          const list = m.reactions ?? [];
          const filtered = list.filter((r) => r.userId !== user.id);
          return { ...m, reactions: [...filtered, optimisticReaction] };
        })
      );

      const revertOptimistic = (): void => {
        get().setMessages((previous) =>
          previous.map((m) => {
            if (m.id !== messageId) {
              return m;
            }
            const list = (m.reactions ?? []).filter((r) => r.id !== optimisticId);
            return { ...m, reactions: list };
          })
        );
      };

      void (async (): Promise<void> => {
        const socket = getChatSocket();
        if (!socket?.connected) {
          revertOptimistic();
          get().setError('Not connected — cannot send reaction');
          return;
        }

        try {
          await chatEmitWithAck<unknown>('react_message', {
            messageId,
            conversationId,
            reactionType: emoji
          });
        } catch (err) {
          revertOptimistic();
          get().setError(err instanceof Error ? err.message : 'Failed to react');
        }
      })();
    },

    handleDelete: async (_messageId: string) => {
      get().setError('Deleting messages is not supported on this server.');
    },

    handleMarkRead: async (messageId) => {
      const conversationId = get().selectedConversationId;
      if (!conversationId) {
        return;
      }
      try {
        await chatEmitWithAck('message_read', { conversationId, messageId });
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to mark as read');
      }
    },

    handleTranscribeVoiceMessage: async (message) => {
      const conversationId = message.conversationId || get().selectedConversationId;
      if (!conversationId) {
        get().setError('No conversation selected');
        return;
      }
      const id = message.id;
      get().patchMessageSpeechUi(id, { loading: 'transcribe', error: undefined });
      try {
        const updated = await conversationsApi.postMessageTranscribe(conversationId, id);
        const text = updated.transcribedMessage?.trim() ?? '';
        get().patchMessageSpeechUi(id, { loading: undefined, transcript: text });
        get().setMessages((previous) =>
          previous.map((m) =>
            m.id === id
              ? {
                  ...m,
                  transcribedMessage: updated.transcribedMessage,
                  translatedMessage: updated.translatedMessage ?? m.translatedMessage,
                  content: updated.content,
                  attachments: updated.attachments?.length ? updated.attachments : m.attachments
                }
              : m
          )
        );
      } catch (err) {
        get().patchMessageSpeechUi(id, {
          loading: undefined,
          error: err instanceof Error ? err.message : 'Transcription failed'
        });
      }
    },

    handleTranslateForMessage: async (message, _sourceText, _targetLanguage) => {
      const conversationId = message.conversationId || get().selectedConversationId;
      if (!conversationId) {
        get().setError('No conversation selected');
        return;
      }
      const id = message.id;
      get().patchMessageSpeechUi(id, { loading: 'translate', error: undefined });
      try {
        const updated = await conversationsApi.postMessageTranslate(conversationId, id);
        const translated = updated.translatedMessage?.trim() ?? '';
        get().patchMessageSpeechUi(id, {
          loading: undefined,
          translated
        });
        get().setMessages((previous) =>
          previous.map((m) =>
            m.id === id
              ? {
                  ...m,
                  translatedMessage: updated.translatedMessage,
                  transcribedMessage: updated.transcribedMessage ?? m.transcribedMessage,
                  content: updated.content,
                  attachments: updated.attachments?.length ? updated.attachments : m.attachments
                }
              : m
          )
        );
      } catch (err) {
        get().patchMessageSpeechUi(id, {
          loading: undefined,
          error: err instanceof Error ? err.message : 'Translation failed'
        });
      }
    }
  };
}
