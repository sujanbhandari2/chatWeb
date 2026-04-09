import { useEffect, useId, useRef } from 'react';
import type { DeliveredReceipt, Message, ReadReceipt } from '../types/chat';
import { WidgetPanelType } from '../types/chat';
import { useChatSocket } from './useChatSocket';
import { SELECTED_CONVERSATION_STORAGE_KEY } from '../constants/session.constants';
import { CLIENT_GOING_OFFLINE_EVENT } from '../features/chat/chat.constants';
import { setChatSocketInstance } from '../utils/chat-socket-bridge';
import { pickPresence, pickUserId } from '../utils/chat.utils';
import { useAuthStore } from '../store/useAuthStore';
import { useChatSelectors } from './useChatSelectors';
import { selectRuntimeSubscriptionSlice } from '../store/chat/chat-selectors';
import { useChatStore } from '../store/useChatStore';
import type { WidgetInitConfig } from '../schemas/widget.schemas';
import type { ChatRuntimeValue } from '../types/chat-runtime.types';

type SocketAck<T> = { ok: boolean; data?: T; error?: string };

/** Socket sync, scroll, menus, recording, and bootstrap for the chat UI. */
export function useChatRuntime(widgetConfig: WidgetInitConfig): ChatRuntimeValue {
  const { voiceRecording } = widgetConfig.features;
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const clearSession = useAuthStore((s) => s.clearSession);
  const socket = useChatSocket(token || undefined);

  const messageScrollerRef = useRef<HTMLElement | null>(null);
  const chatHeaderMenuRef = useRef<HTMLDivElement | null>(null);
  const chatsListOverflowMenuRef = useRef<HTMLDivElement | null>(null);
  const lastAutoScrollKeyRef = useRef<string>('');
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const audioStreamRef = useRef<MediaStream | null>(null);
  const discardRecordingRef = useRef<boolean>(false);

  const newGroupFormId = useId().replace(/:/g, '');
  const editGroupFormId = useId().replace(/:/g, '');

  useEffect(() => {
    setChatSocketInstance(socket ?? null);
    return () => setChatSocketInstance(null);
  }, [socket]);

  const {
    selectedConversationId,
    messages,
    messageActionsMenuId,
    isRecording,
    widgetRailPane,
    creatingGroup,
    editGroupSaving,
    chatHeaderMenuOpen,
    widgetInboxMenuOpen,
    conversations,
  } = useChatSelectors(selectRuntimeSubscriptionSlice);

  useEffect(() => {
    if (!isRecording) {
      useChatStore.getState().setRecordingDurationMs(0);
      return;
    }
    const startedAt = Date.now();
    const tick = window.setInterval(() => {
      useChatStore.getState().setRecordingDurationMs(Date.now() - startedAt);
    }, 200);
    return () => window.clearInterval(tick);
  }, [isRecording]);

  useEffect(() => {
    if (!messageActionsMenuId) {
      return undefined;
    }
    const close = (event: MouseEvent): void => {
      const root = document.querySelector(`[data-message-menu-root="${messageActionsMenuId}"]`);
      if (root && !root.contains(event.target as Node)) {
        useChatStore.getState().setMessageActionsMenuId(null);
      }
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        useChatStore.getState().setMessageActionsMenuId(null);
      }
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', onKey);
    };
  }, [messageActionsMenuId]);

  useEffect(() => {
    useChatStore.getState().clearMessageSpeechOnConversationChange();
  }, [selectedConversationId]);

  useEffect(() => {
    if (!selectedConversationId) {
      return;
    }
    const lastMessageId = messages.length > 0 ? messages[messages.length - 1].id : '';
    const autoScrollKey = `${selectedConversationId}:${lastMessageId}:${messages.length}`;
    if (autoScrollKey === lastAutoScrollKeyRef.current) {
      return;
    }
    lastAutoScrollKeyRef.current = autoScrollKey;
    const scroller = messageScrollerRef.current;
    if (!scroller) {
      return;
    }
    window.requestAnimationFrame(() => {
      scroller.scrollTo({
        top: scroller.scrollHeight,
        behavior: 'smooth'
      });
    });
  }, [messages, selectedConversationId]);

  useEffect(() => {
    try {
      if (selectedConversationId) {
        window.localStorage.setItem(SELECTED_CONVERSATION_STORAGE_KEY, selectedConversationId);
      } else {
        window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
      }
    } catch {
      window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
    }
  }, [selectedConversationId]);

  useEffect(() => {
    if (!widgetInboxMenuOpen) {
      return;
    }
    const onMouseDown = (event: MouseEvent): void => {
      if (chatsListOverflowMenuRef.current?.contains(event.target as Node)) {
        return;
      }
      useChatStore.getState().setWidgetInboxMenuOpen(false);
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => document.removeEventListener('mousedown', onMouseDown);
  }, [widgetInboxMenuOpen]);

  useEffect(() => {
    if (widgetRailPane !== WidgetPanelType.NEW_GROUP || creatingGroup) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        useChatStore.getState().exitNewGroupRailToChats();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [widgetRailPane, creatingGroup]);

  useEffect(() => {
    if (widgetRailPane !== WidgetPanelType.EDIT_GROUP || editGroupSaving) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        useChatStore.getState().exitEditGroupRailToChats();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [widgetRailPane, editGroupSaving]);

  useEffect(() => {
    if (!chatHeaderMenuOpen) {
      return;
    }
    const onMouseDown = (event: MouseEvent): void => {
      if (chatHeaderMenuRef.current?.contains(event.target as Node)) {
        return;
      }
      useChatStore.getState().setChatHeaderMenuOpen(false);
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => document.removeEventListener('mousedown', onMouseDown);
  }, [chatHeaderMenuOpen]);

  useEffect(() => {
    if (!socket || !user) {
      return undefined;
    }

    const newSocket = socket;

    const updateUserPresence = (userId: string, isOnline: boolean): void => {
      useChatStore.getState().updateTenantUserOnline(userId, isOnline);
    };

    const onPresencePayload = (payload: unknown): void => {
      const parsed = pickPresence(payload);
      if (parsed) {
        updateUserPresence(parsed.userId, parsed.isOnline);
      }
    };

    const onOnlinePayload = (payload: unknown): void => {
      const id = pickUserId(payload);
      if (id) {
        updateUserPresence(id, true);
      }
    };

    const onOfflinePayload = (payload: unknown): void => {
      const id = pickUserId(payload);
      if (id) {
        updateUserPresence(id, false);
      }
    };

    const presenceEvents: Array<[string, (p: unknown) => void]> = [
      ['presence_update', onPresencePayload],
      ['user_presence', onPresencePayload],
      ['presence', onPresencePayload],
      ['presence_change', onPresencePayload],
      ['user_online', onOnlinePayload],
      ['user:online', onOnlinePayload],
      ['USER_ONLINE', onOnlinePayload],
      ['user_offline', onOfflinePayload],
      ['user:offline', onOfflinePayload],
      ['USER_OFFLINE', onOfflinePayload]
    ];

    for (const [event, handler] of presenceEvents) {
      newSocket.on(event, handler);
    }

    const onPresenceState = (payload: unknown): void => {
      if (!payload || typeof payload !== 'object') {
        return;
      }
      const record = payload as Record<string, unknown>;
      const map = record.map as Record<string, boolean> | undefined;
      if (!map || typeof map !== 'object') {
        return;
      }
      useChatStore.getState().applyTenantPresenceMap(map);
    };

    const onOnlineUsersList = (payload: unknown): void => {
      if (!payload || typeof payload !== 'object') {
        return;
      }
      const record = payload as Record<string, unknown>;
      const ids = record.userIds ?? record.user_ids ?? record.ids;
      if (!Array.isArray(ids)) {
        return;
      }
      useChatStore.getState().setAllTenantOnlineFromIds(ids);
    };

    newSocket.on('presence_state', onPresenceState);
    newSocket.on('online_users', onOnlineUsersList);

    const onSocketConnect = (): void => {
      useChatStore.getState().setSocketConnected(true);
    };

    const onSocketDisconnect = (): void => {
      useChatStore.getState().setSocketConnected(false);
    };

    newSocket.on('connect', onSocketConnect);
    newSocket.on('disconnect', onSocketDisconnect);

    newSocket.on('message_received', (message: Message) => {
      const store = useChatStore.getState();
      const authUser = useAuthStore.getState().user;
      store.bumpConversationUpdatedAt(message.conversationId, message.createdAt);

      const isOwnMessage = message.senderId === authUser?.id;
      if (!isOwnMessage) {
        newSocket.emit('mark_as_delivered', { messageId: message.id }, () => undefined);
      }

      if (message.conversationId === store.selectedConversationId) {
        store.upsertMessage(message);
        if (!isOwnMessage) {
          newSocket.emit('mark_as_read', { messageId: message.id }, () => undefined);
        }
        return;
      }

      if (!isOwnMessage) {
        store.setUnreadByConversation((previous) => ({
          ...previous,
          [message.conversationId]: (previous[message.conversationId] ?? 0) + 1
        }));
      }
    });

    const applyReactionFromSocket = useChatStore.getState().applyReactionFromSocket;
    newSocket.on('message_reacted', applyReactionFromSocket);
    newSocket.on('reaction_added', applyReactionFromSocket);

    const onMessageDeleted = (payload: { messageId: string; conversationId: string; deletedAt: string }): void => {
      useChatStore.getState().applyMessageDeleted(payload);
    };
    newSocket.on('message_deleted', onMessageDeleted);

    const onDelivered = (receipt: DeliveredReceipt & { conversationId?: string }): void => {
      useChatStore.getState().applyDeliveredReceipt(receipt);
    };
    newSocket.on('message_delivered', onDelivered);

    const onRead = (receipt: ReadReceipt & { conversationId?: string }): void => {
      useChatStore.getState().applyReadReceipt(receipt);
    };
    newSocket.on('message_read', onRead);

    newSocket.on('connect_error', (connectionError) => {
      useChatStore.getState().setError(`Realtime connection failed: ${connectionError.message}`);
    });

    if (newSocket.connected) {
      useChatStore.getState().setSocketConnected(true);
    }

    const offlineUserId = user?.id;

    const emitGoingOffline = (reason: string): void => {
      if (!offlineUserId || !newSocket.connected) {
        return;
      }
      newSocket.emit(CLIENT_GOING_OFFLINE_EVENT, { userId: offlineUserId, reason });
    };

    const onPageLeave = (): void => {
      emitGoingOffline('page_unload');
    };

    window.addEventListener('pagehide', onPageLeave);
    window.addEventListener('beforeunload', onPageLeave);

    return () => {
      window.removeEventListener('pagehide', onPageLeave);
      window.removeEventListener('beforeunload', onPageLeave);
      for (const [event, handler] of presenceEvents) {
        newSocket.off(event, handler);
      }
      newSocket.off('presence_state', onPresenceState);
      newSocket.off('online_users', onOnlineUsersList);
      newSocket.off('connect', onSocketConnect);
      newSocket.off('disconnect', onSocketDisconnect);
      newSocket.off('message_received');
      newSocket.off('message_reacted', applyReactionFromSocket);
      newSocket.off('reaction_added', applyReactionFromSocket);
      newSocket.off('message_deleted', onMessageDeleted);
      newSocket.off('message_delivered', onDelivered);
      newSocket.off('message_read', onRead);
      newSocket.off('connect_error');
      useChatStore.getState().setSocketConnected(false);
    };
  }, [socket, user?.id]);

  useEffect(() => {
    if (!socket || !selectedConversationId || !user) {
      return;
    }

    messages.forEach((message) => {
      if (message.senderId === user.id || message.deletedAt) {
        return;
      }

      const deliveredReceipts = message.deliveredReceipts ?? [];
      const readReceipts = message.readReceipts ?? [];

      if (!deliveredReceipts.some((item) => item.userId === user.id)) {
        socket.emit('mark_as_delivered', { messageId: message.id }, () => undefined);
      }

      if (!readReceipts.some((item) => item.userId === user.id)) {
        socket.emit('mark_as_read', { messageId: message.id }, () => undefined);
      }
    });
  }, [socket, selectedConversationId, messages, user]);

  useEffect(() => {
    if (!socket || conversations.length === 0) {
      return;
    }

    const joinAllConversations = (): void => {
      conversations.forEach((conversation) => {
        socket.emit(
          'join_conversation',
          { conversationId: conversation.id },
          (response: SocketAck<{ conversationId: string }>) => {
            if (!response.ok) {
              useChatStore.getState().setError(response.error ?? 'Failed to join conversation');
            }
          }
        );
      });
    };

    if (socket.connected) {
      joinAllConversations();
    } else {
      socket.once('connect', joinAllConversations);
    }

    return () => {
      socket.off('connect', joinAllConversations);
    };
  }, [socket, conversations]);

  useEffect(() => {
    if (!token) {
      return;
    }

    const interval = window.setInterval(() => {
      void useChatStore.getState().refreshUsers();
    }, 8000);

    return () => window.clearInterval(interval);
  }, [token]);

  useEffect(() => {
    if (!token || !user) {
      return;
    }

    let cancelled = false;
    const bootstrap = async (): Promise<void> => {
      try {
        await useChatStore.getState().bootstrapChatApp();
      } catch (err) {
        if (cancelled) {
          return;
        }
        useChatStore.getState().setError(err instanceof Error ? err.message : 'Session expired');
        clearSession();
        useChatStore.getState().reset();
        window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
      }
    };

    void bootstrap();

    return () => {
      cancelled = true;
    };
  }, [token, user, clearSession]);

  useEffect(() => {
    if (!token) {
      useChatStore.getState().reset();
    }
  }, [token]);

  const startRecording = async (): Promise<void> => {
    if (!voiceRecording) {
      return;
    }
    const store = useChatStore.getState();
    const authToken = useAuthStore.getState().token;
    if (!authToken || !store.selectedConversationId || store.isRecording) {
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
      store.setError('Browser does not support audio recording');
      return;
    }

    try {
      discardRecordingRef.current = false;
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      audioChunksRef.current = [];
      audioStreamRef.current = stream;

      recorder.ondataavailable = (recordEvent) => {
        if (recordEvent.data.size > 0) {
          audioChunksRef.current.push(recordEvent.data);
        }
      };

      recorder.onstop = async () => {
        audioStreamRef.current?.getTracks().forEach((track) => track.stop());
        audioStreamRef.current = null;
        mediaRecorderRef.current = null;

        if (discardRecordingRef.current) {
          discardRecordingRef.current = false;
          return;
        }

        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        const file = new File([audioBlob], `voice-${Date.now()}.webm`, { type: 'audio/webm' });
        await useChatStore.getState().handleSendUploadedMessage(file, 'VOICE');
      };

      recorder.start();
      mediaRecorderRef.current = recorder;
      store.setIsRecording(true);
    } catch (err) {
      store.setError(err instanceof Error ? err.message : 'Failed to start recording');
    }
  };

  const finishRecording = (): void => {
    const recorder = mediaRecorderRef.current;
    if (!recorder || recorder.state === 'inactive') {
      useChatStore.getState().setIsRecording(false);
      return;
    }
    discardRecordingRef.current = false;
    recorder.stop();
    useChatStore.getState().setIsRecording(false);
  };

  const cancelRecording = (): void => {
    const recorder = mediaRecorderRef.current;
    if (!recorder || recorder.state === 'inactive') {
      audioStreamRef.current?.getTracks().forEach((track) => track.stop());
      audioStreamRef.current = null;
      mediaRecorderRef.current = null;
      useChatStore.getState().setIsRecording(false);
      return;
    }
    discardRecordingRef.current = true;
    recorder.stop();
    useChatStore.getState().setIsRecording(false);
  };

  return {
    messageScrollerRef,
    chatHeaderMenuRef,
    chatsListOverflowMenuRef,
    newGroupFormId,
    editGroupFormId,
    startRecording,
    finishRecording,
    cancelRecording
  };
}
