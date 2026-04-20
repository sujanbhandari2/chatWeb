import { useCallback, useEffect, useId, useMemo, useRef } from 'react';
import type { ChatSocketHandshakeSession } from '../lib/chat-socket';
import type { DeliveredReceipt, Message, ReadReceipt } from '../types/chat';
import { WidgetPanelType } from '../types/chat';
import { useChatSocket } from './useChatSocket';
import {
  chatRealtimeEvents,
  chatRealtimeLegacyEvents,
  chatSocketClientEvents
} from '../constants/chat-realtime.constants';
import { SELECTED_CONVERSATION_STORAGE_KEY } from '../constants/session.constants';
import { CLIENT_GOING_OFFLINE_EVENT } from '../features/chat/chat.constants';
import { setChatSocketInstance } from '../utils/chat-socket-bridge';
import { pickTypingConversationPayload, pickUserId } from '../utils/chat.utils';
import { ApiError } from '../lib/api-error';
import { getResolvedApiKey } from '../lib/api-credentials';
import { toast } from '../common/ui/Toaster';
import { useAuthStore } from '../store/useAuthStore';
import { useChatSelectors } from './useChatSelectors';
import { selectRuntimeSubscriptionSlice } from '../store/chat/chat-selectors';
import { useChatStore } from '../store/useChatStore';
import type { WidgetInitConfig } from '../schemas/widget.schemas';
import type { ChatRuntimeValue } from '../types/chat-runtime.types';

type JoinConversationAck = { ok: boolean; error?: string };

/** Socket sync, scroll, menus, recording, and bootstrap for the chat UI. */
export function useChatRuntime(widgetConfig: WidgetInitConfig): ChatRuntimeValue {
  const { voiceRecording } = widgetConfig.features;
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const clearSession = useAuthStore((s) => s.clearSession);
  const canUseApi = Boolean(token?.trim() || getResolvedApiKey());
  const apiKey = getResolvedApiKey();

  if (!apiKey) {
    console.error('No API key found');
  }

  const socketHandshakeSession = useMemo((): ChatSocketHandshakeSession | undefined => {
    const t = token?.trim();
    const uid = user?.id?.trim();
    if (t && uid) {
      return { token: t, userId: uid };
    }
    return undefined;
  }, [token, user?.id]);

  const socket = useChatSocket(apiKey ?? '', socketHandshakeSession);

  const messageScrollerRef = useRef<HTMLElement | null>(null);
  const chatHeaderMenuRef = useRef<HTMLDivElement | null>(null);
  const chatsListOverflowMenuRef = useRef<HTMLDivElement | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const audioStreamRef = useRef<MediaStream | null>(null);
  const discardRecordingRef = useRef<boolean>(false);
  /** Browser `setTimeout` id (`number`); avoid `NodeJS.Timeout` from `@types/node` merge. */
  const typingStopTimerRef = useRef<number | null>(null);
  const typingStartedRef = useRef(false);
  const previousThreadIdRef = useRef<string | undefined>(undefined);

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

    const onUserTyping = (payload: unknown): void => {
      const parsed = pickTypingConversationPayload(payload);
      if (!parsed) {
        return;
      }
      useChatStore
        .getState()
        .applyRemoteTypingStart(parsed.conversationId, parsed.userId, user?.id);
    };

    const onUserStoppedTyping = (payload: unknown): void => {
      const parsed = pickTypingConversationPayload(payload);
      if (!parsed) {
        return;
      }
      useChatStore.getState().applyRemoteTypingStop(parsed.conversationId, parsed.userId);
    };

    newSocket.on(chatRealtimeEvents.userOnline, onOnlinePayload);
    newSocket.on(chatRealtimeEvents.userOffline, onOfflinePayload);
    newSocket.on(chatRealtimeEvents.userTyping, onUserTyping);
    newSocket.on(chatRealtimeEvents.userStoppedTyping, onUserStoppedTyping);

    const onSocketConnect = (): void => {
      useChatStore.getState().setSocketConnected(true);
    };

    const onSocketDisconnect = (): void => {
      useChatStore.getState().setSocketConnected(false);
    };

    newSocket.on('connect', onSocketConnect);
    newSocket.on('disconnect', onSocketDisconnect);

    const emitDelivery = (conversationId: string, messageId: string): void => {
      newSocket.emit(
        chatSocketClientEvents.messageDelivered,
        { conversationId, messageId },
        () => undefined
      );
    };

    const emitRead = (conversationId: string, messageId: string): void => {
      newSocket.emit(chatSocketClientEvents.messageRead, { conversationId, messageId }, () => undefined);
    };

    newSocket.on(chatRealtimeEvents.message, (message: Message) => {
      const store = useChatStore.getState();
      const authUser = useAuthStore.getState().user;
      store.bumpConversationUpdatedAt(message.conversationId, message.createdAt);

      const isOwnMessage = message.senderId === authUser?.id;
      if (!isOwnMessage) {
        emitDelivery(message.conversationId, message.id);
      }

      if (message.conversationId === store.selectedConversationId) {
        store.upsertMessage(message);
        if (!isOwnMessage) {
          emitRead(message.conversationId, message.id);
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
    newSocket.on(chatRealtimeEvents.reactionAdded, applyReactionFromSocket);

    const onMessageDeleted = (payload: { messageId: string; conversationId: string; deletedAt: string }): void => {
      useChatStore.getState().applyMessageDeleted(payload);
    };
    newSocket.on(chatRealtimeLegacyEvents.messageDeleted, onMessageDeleted);

    const onDelivered = (receipt: DeliveredReceipt & { conversationId?: string }): void => {
      useChatStore.getState().applyDeliveredReceipt(receipt);
    };
    newSocket.on(chatRealtimeEvents.messageDelivered, onDelivered);

    const onRead = (receipt: ReadReceipt & { conversationId?: string }): void => {
      useChatStore.getState().applyReadReceipt(receipt);
    };
    newSocket.on(chatRealtimeEvents.messageRead, onRead);

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
      newSocket.off(chatRealtimeEvents.userOnline, onOnlinePayload);
      newSocket.off(chatRealtimeEvents.userOffline, onOfflinePayload);
      newSocket.off(chatRealtimeEvents.userTyping, onUserTyping);
      newSocket.off(chatRealtimeEvents.userStoppedTyping, onUserStoppedTyping);
      newSocket.off('connect', onSocketConnect);
      newSocket.off('disconnect', onSocketDisconnect);
      newSocket.off(chatRealtimeEvents.message);
      newSocket.off(chatRealtimeEvents.reactionAdded, applyReactionFromSocket);
      newSocket.off(chatRealtimeLegacyEvents.messageDeleted, onMessageDeleted);
      newSocket.off(chatRealtimeEvents.messageDelivered, onDelivered);
      newSocket.off(chatRealtimeEvents.messageRead, onRead);
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
        socket.emit(
          chatSocketClientEvents.messageDelivered,
          { conversationId: selectedConversationId, messageId: message.id },
          () => undefined
        );
      }

      if (!readReceipts.some((item) => item.userId === user.id)) {
        socket.emit(
          chatSocketClientEvents.messageRead,
          { conversationId: selectedConversationId, messageId: message.id },
          () => undefined
        );
      }
    });
  }, [socket, selectedConversationId, messages, user]);

  useEffect(() => {
    if (!socket || !user?.id || !selectedConversationId?.trim()) {
      return undefined;
    }

    const conversationId = selectedConversationId.trim();

    const join = (): void => {
      socket.emit(
        chatSocketClientEvents.joinConversation,
        { conversationId },
        (response: unknown) => {
          if (
            response &&
            typeof response === 'object' &&
            'ok' in response &&
            (response as JoinConversationAck).ok === false
          ) {
            useChatStore
              .getState()
              .setError((response as JoinConversationAck).error ?? 'Failed to join conversation');
          }
        }
      );
    };

    socket.on('connect', join);
    if (socket.connected) {
      join();
    }

    return () => {
      socket.off('connect', join);
      socket.emit(
        chatSocketClientEvents.leaveConversation,
        { conversationId },
        () => undefined
      );
    };
  }, [socket, selectedConversationId, user?.id]);

  useEffect(() => {
    const prev = previousThreadIdRef.current;
    previousThreadIdRef.current = selectedConversationId || undefined;
    typingStartedRef.current = false;
    if (typingStopTimerRef.current) {
      window.clearTimeout(typingStopTimerRef.current);
      typingStopTimerRef.current = null;
    }
    if (prev?.trim() && socket?.connected) {
      socket.emit(
        chatSocketClientEvents.typingStop,
        { conversationId: prev.trim() },
        () => undefined
      );
    }
  }, [selectedConversationId, socket]);

  const notifyComposerTyping = useCallback((): void => {
    if (!socket?.connected || !selectedConversationId?.trim()) {
      return;
    }
    const conversationId = selectedConversationId.trim();
    if (!typingStartedRef.current) {
      typingStartedRef.current = true;
      socket.emit(chatSocketClientEvents.typingStart, { conversationId }, () => undefined);
    }
    if (typingStopTimerRef.current) {
      window.clearTimeout(typingStopTimerRef.current);
    }
    typingStopTimerRef.current = window.setTimeout(() => {
      typingStopTimerRef.current = null;
      if (socket.connected && typingStartedRef.current) {
        typingStartedRef.current = false;
        socket.emit(chatSocketClientEvents.typingStop, { conversationId }, () => undefined);
      }
    }, 2000);
  }, [socket, selectedConversationId]);

  useEffect(() => {
    if (!canUseApi || !user) {
      return;
    }

    let cancelled = false;
    const bootstrap = async (): Promise<void> => {
      try {
        await useChatStore.getState().bootstrapChatApp();
        if (!cancelled) {
          useChatStore.getState().setError('');
        }
      } catch (err) {
        if (cancelled) {
          return;
        }
        const message = err instanceof Error ? err.message : 'Could not load chat';
        useChatStore.getState().setError(message);
        const status = err instanceof ApiError ? err.status : 0;
        if (status === 401) {
          if (!getResolvedApiKey()) {
            clearSession();
            useChatStore.getState().reset();
            window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
          } else {
            /** Same idea as `axios` 401: chat works with API key — drop bad JWT, do not wipe chat user / store. */
            useAuthStore.getState().clearTokenKeepUser();
            toast(message);
          }
        } else {
          toast(message);
        }
      }
    };

    void bootstrap();

    return () => {
      cancelled = true;
    };
  }, [canUseApi, user, clearSession]);

  useEffect(() => {
    if (!user) {
      useChatStore.getState().reset();
    }
  }, [user]);

  const startRecording = async (): Promise<void> => {
    if (!voiceRecording) {
      return;
    }
    const store = useChatStore.getState();
    const authToken = useAuthStore.getState().token;
    if ((!authToken?.trim() && !getResolvedApiKey()) || !store.selectedConversationId || store.isRecording) {
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
    cancelRecording,
    notifyComposerTyping
  };
}
