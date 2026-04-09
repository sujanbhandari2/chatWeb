/**
 * Actions that talk to the backend: REST, uploads, socket acks, and speech APIs.
 */
import type { FormEvent } from 'react';
import * as conversationsApi from '../../api/conversations.api';
import { getTenantUsers } from '../../api/users.api';
import { uploadFileRequest } from '../../api/upload.api';
import { transcribeSpeechRequest, translateTextRequest } from '../../api/speech.api';
import { fetchMediaBlob } from '../../utils/media.utils';
import { ApiError } from '../../lib/api-error';
import { isGlobalConversation, normalizeMessage } from '../../utils/chat.utils';
import { WidgetPanelType, type Message, type MessageReaction, type MessageType } from '../../types/chat';
import { SELECTED_CONVERSATION_STORAGE_KEY } from '../../constants/session.constants';
import { CLIENT_GOING_OFFLINE_EVENT } from '../../features/chat/chat.constants';
import { chatEmitWithAck, getChatSocket } from '../../utils/chat-socket-bridge';
import { useAuthStore } from '../useAuthStore';
import type { ChatStore } from './chatStore.types';
import { conversationTitleForUser, findDirectConversation } from './chatStore.utils';

type SetChat = {
  (
    partial: ChatStore | Partial<ChatStore> | ((state: ChatStore) => ChatStore | Partial<ChatStore>),
    replace?: false | undefined
  ): void;
};

type SocketAck<T> = { ok: boolean; data?: T; error?: string };

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
      get().setError('');
      get().setSelectedConversationId(conversationId);
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
      const data = await conversationsApi.listConversations();
      get().setConversations(data);
      return data;
    },

    refreshUsers: async () => {
      const data = await getTenantUsers();
      get().setTenantUsers(data);
    },

    bootstrapChatApp: async () => {
      const [loadedConversations] = await Promise.all([get().refreshConversations(), get().refreshUsers()]);
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
        const createdConversation = await conversationsApi.createDirectConversation(target.id);
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
        const created = await conversationsApi.createGroupConversation(title, participantIds);
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
        editGroupTitle,
        editGroupParticipantIds,
        editGroupInitialParticipantIds: initialIds
      } = get();
      const title = editGroupTitle.trim();
      if (title.length < 1 || title.length > 120) {
        get().setEditGroupError('Group name must be 1–120 characters.');
        return;
      }
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
        await conversationsApi.updateConversationById(convId, { title });

        const added = [...current].filter((id) => !initial.has(id));
        const removed = [...initial].filter((id) => !current.has(id));
        const removedOthers = removed.filter((id) => id !== user.id);

        if (added.length > 0) {
          await conversationsApi.addConversationParticipants(convId, added);
        }
        for (const uid of removedOthers) {
          await conversationsApi.removeConversationParticipant(convId, uid);
        }
        if (removedSelf) {
          await conversationsApi.removeConversationParticipant(convId, user.id);
        }

        get().setWidgetRailPane(WidgetPanelType.CHATS);
        await get().refreshConversations();
        if (removedSelf) {
          get().setSelectedConversationId('');
          get().setMessages([]);
        } else {
          await get().selectConversation(convId);
        }
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
        await conversationsApi.removeConversationParticipant(convId, user.id);
        get().setWidgetRailPane(WidgetPanelType.CHATS);
        await get().refreshConversations();
        get().setSelectedConversationId('');
        get().setMessages([]);
      } catch (err) {
        get().setEditGroupError(err instanceof Error ? err.message : 'Could not leave group');
      } finally {
        get().setEditGroupSaving(false);
      }
    },

    handleDeleteSelectedConversation: async () => {
      const token = useAuthStore.getState().token;
      const user = useAuthStore.getState().user;
      const { conversations, selectedConversationId } = get();
      const selectedConversation =
        conversations.find((conversation) => conversation.id === selectedConversationId) ?? null;
      if (!token || !selectedConversation || !user) {
        return;
      }
      if (isGlobalConversation(selectedConversation)) {
        window.alert('This channel cannot be deleted here.');
        get().setChatHeaderMenuOpen(false);
        return;
      }
      const label = conversationTitleForUser(selectedConversation, user);
      if (!window.confirm(`Delete “${label}”? This removes the chat for you.`)) {
        return;
      }
      get().setDeletingConversation(true);
      get().setChatHeaderMenuOpen(false);
      get().setError('');
      try {
        const id = selectedConversation.id;
        await conversationsApi.deleteConversationById(id);
        await get().refreshConversations();
        get().setSelectedConversationId('');
        get().setMessages([]);
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to delete conversation');
      } finally {
        get().setDeletingConversation(false);
      }
    },

    handleSendText: async () => {
      const { selectedConversationId, text } = get();
      if (!selectedConversationId || !text.trim()) {
        return;
      }
      try {
        const message = await chatEmitWithAck<Message>('send_message', {
          conversationId: selectedConversationId,
          type: 'TEXT' as MessageType,
          content: text.trim()
        });
        get().upsertMessage(message);
        get().bumpConversationUpdatedAt(selectedConversationId, message.createdAt);
        get().setText('');
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to send message');
      }
    },

    handleSendUploadedMessage: async (file, type) => {
      const token = useAuthStore.getState().token;
      const { selectedConversationId } = get();
      if (!token || !selectedConversationId) {
        return;
      }
      try {
        const uploaded = await uploadFileRequest(file);
        const message = await chatEmitWithAck<Message>('send_message', {
          conversationId: selectedConversationId,
          type,
          content: uploaded.url
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
        if (token) {
          try {
            const updated = await conversationsApi.addMessageReaction(conversationId, messageId, emoji);
            if (updated && typeof updated === 'object' && 'id' in updated && updated.id === messageId) {
              get().setMessages((previous) =>
                previous.map((m) => (m.id === messageId ? normalizeMessage(updated) : m))
              );
              return;
            }
          } catch (err) {
            const skipSocket =
              err instanceof ApiError && [404, 405, 501].includes(err.status);
            if (!skipSocket) {
              revertOptimistic();
              get().setError(err instanceof Error ? err.message : 'Failed to react');
              return;
            }
          }
        }

        const socket = getChatSocket();
        if (!socket?.connected) {
          revertOptimistic();
          get().setError('Not connected — cannot send reaction');
          return;
        }

        socket.emit(
          'react_to_message',
          {
            messageId,
            conversationId,
            emoji,
            reactionType: emoji
          },
          (response?: SocketAck<unknown>) => {
            if (response === undefined) {
              return;
            }
            if (!response.ok) {
              revertOptimistic();
              get().setError(response.error ?? 'Failed to react');
              return;
            }
            const data = response.data;
            if (
              data &&
              typeof data === 'object' &&
              'reactions' in data &&
              'id' in data &&
              (data as Message).id === messageId
            ) {
              get().setMessages((previous) =>
                previous.map((m) => (m.id === messageId ? normalizeMessage(data as Message) : m))
              );
            }
          }
        );
      })();
    },

    handleDelete: async (messageId) => {
      try {
        await chatEmitWithAck('delete_message', { messageId });
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to delete message');
      }
    },

    handleMarkRead: async (messageId) => {
      try {
        await chatEmitWithAck('mark_as_read', { messageId });
      } catch (err) {
        get().setError(err instanceof Error ? err.message : 'Failed to mark as read');
      }
    },

    handleTranscribeVoiceMessage: async (message) => {
      const token = useAuthStore.getState().token;
      if (!token) {
        get().setError('Sign in required');
        return;
      }
      const id = message.id;
      get().patchMessageSpeechUi(id, { loading: 'transcribe', error: undefined });
      try {
        const blob = await fetchMediaBlob(message.content, token);
        const out = await transcribeSpeechRequest(blob, { filename: 'message.webm' });
        const text = out.data?.text ?? '';
        get().patchMessageSpeechUi(id, { loading: undefined, transcript: text });
      } catch (err) {
        get().patchMessageSpeechUi(id, {
          loading: undefined,
          error: err instanceof Error ? err.message : 'Transcription failed'
        });
      }
    },

    handleTranslateForMessage: async (message, sourceText, targetLanguage) => {
      const token = useAuthStore.getState().token;
      if (!token) {
        get().setError('Sign in required');
        return;
      }
      if (!sourceText.trim()) {
        return;
      }
      const id = message.id;
      get().patchMessageSpeechUi(id, { loading: 'translate', error: undefined });
      try {
        const out = await translateTextRequest({
          text: sourceText,
          targetLanguage
        });
        const translated = out.data?.translatedText ?? '';
        get().patchMessageSpeechUi(id, { loading: undefined, translated });
      } catch (err) {
        get().patchMessageSpeechUi(id, {
          loading: undefined,
          error: err instanceof Error ? err.message : 'Translation failed'
        });
      }
    }
  };
}
