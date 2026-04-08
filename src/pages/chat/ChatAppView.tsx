import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Socket } from 'socket.io-client';
import * as conversationsApi from '../../api/conversations.api';
import { getTenantUsers } from '../../api/users.api';
import { ApiError } from '../../lib/api-error';
import { useChatSocket } from '../../hooks/useChatSocket';
import { SELECTED_CONVERSATION_STORAGE_KEY } from '../../constants/session.constants';
import { uploadFileRequest } from '../../api/upload.api';
import { transcribeSpeechRequest, translateTextRequest } from '../../api/speech.api';
import { fetchMediaBlob, toAbsoluteMediaUrl } from '../../utils/media.utils';
import {
  isGlobalConversation,
  isGroupConversation,
  getMessageType,
  normalizeMessage,
  pickPresence,
  pickUserId,
  summarizeReactions,
  userDisplayName,
  userInitials,
  type UserLabel
} from '../../utils/chat.utils';
import {
  Conversation,
  DeliveredReceipt,
  Message,
  MessageReaction,
  MessageType,
  PublicUser,
  ReadReceipt,
  TenantUser
} from '../../types/chat';
import { ChatWidgetShell } from '../../features/widget/ChatWidgetShell';
import { defaultWidgetInitConfig, type WidgetInitConfig } from '../../schemas/widget.schemas';
import { useAuthStore } from '../../store/useAuthStore';
import { AuthForm } from '../../features/auth/AuthForm';
import {
  CLIENT_GOING_OFFLINE_EVENT,
  QUICK_REACTION_EMOJIS,
  SOCKET_ACK_TIMEOUT_MS,
  TRANSLATE_TARGET_LANGS,
  translateLangLabel
} from '../../features/chat/messenger.constants';

export type ChatAppViewProps = {
  widgetMode?: boolean;
  widgetConfig?: WidgetInitConfig;
};

type SocketAck<T> = { ok: boolean; data?: T; error?: string };
type DeliveryStatus = 'sent' | 'delivered' | 'seen';

type MessageSpeechUiState = {
  transcript?: string;
  translated?: string;
  targetLang?: string;
  loading?: 'transcribe' | 'translate';
  error?: string;
  /** Messenger-style: language row hidden until user taps “See translation” */
  translateToolsOpen?: boolean;
};

function PresenceDot({ online, title }: { online: boolean; title: string }): JSX.Element {
  return (
    <span
      className={`presence-dot ${online ? 'presence-dot--online' : 'presence-dot--offline'}`}
      title={title}
      aria-label={title}
      role="img"
    />
  );
}

function AvatarWithPresence({ online, children }: { online: boolean; children: ReactNode }): JSX.Element {
  return (
    <div className="avatar-with-presence">
      {children}
      <PresenceDot online={online} title={online ? 'Online' : 'Offline'} />
    </div>
  );
}

function IconSend(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={22} height={22} aria-hidden>
      <path
        fill="currentColor"
        d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"
      />
    </svg>
  );
}

function IconAttach(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={22} height={22} aria-hidden>
      <path
        fill="currentColor"
        d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5c0-1.38 1.12-2.5 2.5-2.5s2.5 1.12 2.5 2.5v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5c0 1.38 1.12 2.5 2.5 2.5s2.5-1.12 2.5-2.5V5c0-2.21-1.79-4-4-4s-4 1.79-4 4v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"
      />
    </svg>
  );
}

function IconImage(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={22} height={22} aria-hidden>
      <path
        fill="currentColor"
        d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"
      />
    </svg>
  );
}

/** Classic “REC” — outer ring + solid dot (reads clearly at small sizes). */
function IconRecord(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={24} height={24} aria-hidden>
      <circle cx="12" cy="12" r="9.25" fill="none" stroke="currentColor" strokeWidth="1.65" opacity={0.4} />
      <circle cx="12" cy="12" r="5.25" fill="currentColor" />
    </svg>
  );
}

function IconCheckSend(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={24} height={24} aria-hidden>
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"
      />
    </svg>
  );
}

function formatRecordingDuration(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

const getDeliveryStatus = (message: Message): DeliveryStatus => {
  const readReceipts = message.readReceipts ?? [];
  const deliveredReceipts = message.deliveredReceipts ?? [];

  const hasSeen = readReceipts.some((item) => item.userId !== message.senderId);
  if (hasSeen) {
    return 'seen';
  }

  const hasDelivered = deliveredReceipts.some((item) => item.userId !== message.senderId);
  if (hasDelivered) {
    return 'delivered';
  }

  return 'sent';
};

export default function ChatAppView({ widgetMode = false, widgetConfig }: ChatAppViewProps = {}): JSX.Element {
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const sessionHydrated = useAuthStore((s) => s.sessionHydrated);
  const clearSession = useAuthStore((s) => s.clearSession);
  const socket = useChatSocket(token || undefined);

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [tenantUsers, setTenantUsers] = useState<TenantUser[]>([]);
  const [selectedConversationId, setSelectedConversationId] = useState<string>('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [text, setText] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [openingDirectUserId, setOpeningDirectUserId] = useState<string>('');
  const [peopleSearchQuery, setPeopleSearchQuery] = useState<string>('');
  const [railMenuOpen, setRailMenuOpen] = useState<boolean>(false);
  const railMenuRef = useRef<HTMLDivElement | null>(null);
  const [groupModalOpen, setGroupModalOpen] = useState<boolean>(false);
  const [groupTitle, setGroupTitle] = useState<string>('');
  const [groupSelectedUserIds, setGroupSelectedUserIds] = useState<string[]>([]);
  const [groupPickerSearch, setGroupPickerSearch] = useState<string>('');
  const [creatingGroup, setCreatingGroup] = useState<boolean>(false);
  const [groupModalError, setGroupModalError] = useState<string>('');
  const [chatHeaderMenuOpen, setChatHeaderMenuOpen] = useState<boolean>(false);
  const chatHeaderMenuRef = useRef<HTMLDivElement | null>(null);
  const [messageActionsMenuId, setMessageActionsMenuId] = useState<string | null>(null);
  const [editGroupModalOpen, setEditGroupModalOpen] = useState<boolean>(false);
  const [editGroupTitle, setEditGroupTitle] = useState<string>('');
  const [editGroupParticipantIds, setEditGroupParticipantIds] = useState<string[]>([]);
  const editGroupInitialIdsRef = useRef<string[]>([]);
  const [editGroupConversationId, setEditGroupConversationId] = useState<string>('');
  const [editGroupPickerSearch, setEditGroupPickerSearch] = useState<string>('');
  const [editGroupSaving, setEditGroupSaving] = useState<boolean>(false);
  const [editGroupError, setEditGroupError] = useState<string>('');
  const [deletingConversation, setDeletingConversation] = useState<boolean>(false);
  const [isRecording, setIsRecording] = useState<boolean>(false);
  const [socketConnected, setSocketConnected] = useState<boolean>(false);
  const [unreadByConversation, setUnreadByConversation] = useState<Record<string, number>>({});

  /** Widget left rail: chats home vs full tenant directory. */
  const [widgetRailPane, setWidgetRailPane] = useState<'chats' | 'people'>('chats');
  const [widgetChatSearchQuery, setWidgetChatSearchQuery] = useState<string>('');
  const [widgetInboxMenuOpen, setWidgetInboxMenuOpen] = useState<boolean>(false);
  const widgetInboxMenuRef = useRef<HTMLDivElement | null>(null);

  const selectedConversationRef = useRef<string>('');
  const messageScrollerRef = useRef<HTMLElement | null>(null);
  const lastAutoScrollKeyRef = useRef<string>('');
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const audioStreamRef = useRef<MediaStream | null>(null);
  const discardRecordingRef = useRef<boolean>(false);
  const [recordingDurationMs, setRecordingDurationMs] = useState<number>(0);
  const [messageSpeechUi, setMessageSpeechUi] = useState<Record<string, MessageSpeechUiState>>({});

  const patchMessageSpeechUi = (messageId: string, patch: Partial<MessageSpeechUiState>): void => {
    setMessageSpeechUi((previous) => ({
      ...previous,
      [messageId]: { ...previous[messageId], ...patch }
    }));
  };

  useEffect(() => {
    selectedConversationRef.current = selectedConversationId;
  }, [selectedConversationId]);

  useEffect(() => {
    if (!isRecording) {
      setRecordingDurationMs(0);
      return;
    }
    const startedAt = Date.now();
    const tick = window.setInterval(() => {
      setRecordingDurationMs(Date.now() - startedAt);
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
        setMessageActionsMenuId(null);
      }
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        setMessageActionsMenuId(null);
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
    setMessageActionsMenuId(null);
    setMessageSpeechUi({});
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
    if (!railMenuOpen) {
      return;
    }
    const onMouseDown = (event: MouseEvent): void => {
      if (railMenuRef.current?.contains(event.target as Node)) {
        return;
      }
      setRailMenuOpen(false);
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => document.removeEventListener('mousedown', onMouseDown);
  }, [railMenuOpen]);

  useEffect(() => {
    if (!widgetInboxMenuOpen) {
      return;
    }
    const onMouseDown = (event: MouseEvent): void => {
      if (widgetInboxMenuRef.current?.contains(event.target as Node)) {
        return;
      }
      setWidgetInboxMenuOpen(false);
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => document.removeEventListener('mousedown', onMouseDown);
  }, [widgetInboxMenuOpen]);

  useEffect(() => {
    if (!groupModalOpen) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        setGroupModalOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [groupModalOpen]);

  useEffect(() => {
    if (!chatHeaderMenuOpen) {
      return;
    }
    const onMouseDown = (event: MouseEvent): void => {
      if (chatHeaderMenuRef.current?.contains(event.target as Node)) {
        return;
      }
      setChatHeaderMenuOpen(false);
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => document.removeEventListener('mousedown', onMouseDown);
  }, [chatHeaderMenuOpen]);

  useEffect(() => {
    if (!editGroupModalOpen) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape' && !editGroupSaving) {
        setEditGroupModalOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [editGroupModalOpen, editGroupSaving]);

  const resolvedWidgetConfig = widgetMode ? (widgetConfig ?? defaultWidgetInitConfig) : null;
  const widgetMissingTenant = Boolean(widgetMode && !widgetConfig?.tenantId?.trim());

  const shellWrap = (node: JSX.Element): JSX.Element =>
    resolvedWidgetConfig ? <ChatWidgetShell config={resolvedWidgetConfig}>{node}</ChatWidgetShell> : node;

  const usersById = useMemo(() => {
    return new Map(tenantUsers.map((item) => [item.id, item]));
  }, [tenantUsers]);

  const selectedConversation = useMemo(
    () => conversations.find((conversation) => conversation.id === selectedConversationId) ?? null,
    [conversations, selectedConversationId]
  );

  const sortedConversations = useMemo(() => {
    return [...conversations].sort((a, b) => {
      const unreadA = (unreadByConversation[a.id] ?? 0) > 0 ? 1 : 0;
      const unreadB = (unreadByConversation[b.id] ?? 0) > 0 ? 1 : 0;
      if (unreadA !== unreadB) {
        return unreadB - unreadA;
      }
      const ta = new Date(a.updatedAt).getTime();
      const tb = new Date(b.updatedAt).getTime();
      return tb - ta;
    });
  }, [conversations, unreadByConversation]);

  const sortedTenantPeers = useMemo(() => {
    const byId = new Map<string, TenantUser>();
    for (const tenantUser of tenantUsers) {
      if (tenantUser.id === user?.id) {
        continue;
      }
      if (!byId.has(tenantUser.id)) {
        byId.set(tenantUser.id, tenantUser);
      }
    }
    return [...byId.values()].sort((a, b) => {
      if (a.isOnline !== b.isOnline) {
        return a.isOnline ? -1 : 1;
      }
      return userDisplayName(a).localeCompare(userDisplayName(b));
    });
  }, [tenantUsers, user?.id]);

  /** Peers who already have a 1:1 direct thread with me — hide from "People" to avoid duplicating the chat list. */
  const peerIdsWithDirectChat = useMemo(() => {
    const ids = new Set<string>();
    if (!user) {
      return ids;
    }
    for (const c of conversations) {
      if (isGlobalConversation(c)) {
        continue;
      }
      const others = c.participants.filter((p) => p.userId !== user.id);
      if (others.length === 1) {
        ids.add(others[0].userId);
      }
    }
    return ids;
  }, [conversations, user]);

  const peersWithoutDirectChat = useMemo(
    () => sortedTenantPeers.filter((p) => !peerIdsWithDirectChat.has(p.id)),
    [sortedTenantPeers, peerIdsWithDirectChat]
  );

  const filteredPeersForNewChat = useMemo(() => {
    const q = peopleSearchQuery.trim().toLowerCase();
    if (!q) {
      return peersWithoutDirectChat;
    }
    return peersWithoutDirectChat.filter((peer) => {
      const name = userDisplayName(peer).toLowerCase();
      const email = peer.email.toLowerCase();
      const status = (peer.status ?? '').toLowerCase();
      return (
        name.includes(q) ||
        email.includes(q) ||
        status.includes(q) ||
        peer.id.toLowerCase().includes(q)
      );
    });
  }, [peersWithoutDirectChat, peopleSearchQuery]);

  /** Widget “People” pane: all tenant peers (not only those without a DM yet). */
  const widgetAllPeopleFiltered = useMemo(() => {
    const q = peopleSearchQuery.trim().toLowerCase();
    if (!q) {
      return sortedTenantPeers;
    }
    return sortedTenantPeers.filter((peer) => {
      const name = userDisplayName(peer).toLowerCase();
      const email = peer.email.toLowerCase();
      const status = (peer.status ?? '').toLowerCase();
      return (
        name.includes(q) ||
        email.includes(q) ||
        status.includes(q) ||
        peer.id.toLowerCase().includes(q)
      );
    });
  }, [sortedTenantPeers, peopleSearchQuery]);

  const filteredGroupPickerPeers = useMemo(() => {
    const selected = new Set(groupSelectedUserIds);
    const q = groupPickerSearch.trim().toLowerCase();
    return sortedTenantPeers
      .filter((p) => !selected.has(p.id))
      .filter((p) => {
        if (!q) {
          return true;
        }
        return (
          userDisplayName(p).toLowerCase().includes(q) ||
          p.email.toLowerCase().includes(q) ||
          (p.status ?? '').toLowerCase().includes(q)
        );
      });
  }, [sortedTenantPeers, groupSelectedUserIds, groupPickerSearch]);

  const filteredEditGroupPickerPeers = useMemo(() => {
    const memberSet = new Set(editGroupParticipantIds);
    const q = editGroupPickerSearch.trim().toLowerCase();
    return sortedTenantPeers
      .filter((p) => !memberSet.has(p.id))
      .filter((p) => {
        if (!q) {
          return true;
        }
        return (
          userDisplayName(p).toLowerCase().includes(q) ||
          p.email.toLowerCase().includes(q) ||
          (p.status ?? '').toLowerCase().includes(q)
        );
      });
  }, [sortedTenantPeers, editGroupParticipantIds, editGroupPickerSearch]);

  const isPeerOnline = (userId: string): boolean => usersById.get(userId)?.isOnline ?? false;

  const displayNameForParticipantId = (userId: string): string => {
    const tenant = usersById.get(userId);
    if (tenant) {
      return userDisplayName(tenant);
    }
    const fromConv = selectedConversation?.participants.find((p) => p.userId === userId)?.user;
    if (fromConv) {
      return userDisplayName(fromConv);
    }
    return userId.slice(0, 8);
  };

  const getSingleOtherParticipantId = (conversation: Conversation): string | undefined => {
    if (!user || isGlobalConversation(conversation)) {
      return undefined;
    }
    const others = conversation.participants.filter((p) => p.userId !== user.id);
    return others.length === 1 ? others[0].userId : undefined;
  };

  const selectedDirectPeerId = useMemo(() => {
    if (!selectedConversation || !user || isGlobalConversation(selectedConversation)) {
      return undefined;
    }
    const others = selectedConversation.participants.filter((p) => p.userId !== user.id);
    return others.length === 1 ? others[0].userId : undefined;
  }, [selectedConversation, user]);

  const upsertMessage = (incoming: Message): void => {
    const normalized = normalizeMessage(incoming);
    setMessages((previous) => {
      const existingIndex = previous.findIndex((message) => message.id === normalized.id);
      if (existingIndex === -1) {
        return [...previous, normalized];
      }

      const next = [...previous];
      next[existingIndex] = normalized;
      return next;
    });
  };

  /** Keep sidebar order in sync with latest message without waiting for a full refresh */
  const bumpConversationUpdatedAt = (conversationId: string, iso: string): void => {
    setConversations((previous) =>
      previous.map((c) => {
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
    );
  };

  const getConversationTitle = (conversation: Conversation): string => {
    if (isGlobalConversation(conversation)) {
      return 'System Broadcast (All Users)';
    }

    if (conversation.title?.trim()) {
      return conversation.title.trim();
    }

    if (!user) {
      return 'Conversation';
    }

    const others = conversation.participants.filter((item) => item.userId !== user.id);

    if (others.length === 0) {
      return 'Just You';
    }

    if (others.length === 1) {
      return userDisplayName(others[0].user);
    }

    return `${userDisplayName(others[0].user)} + ${others.length - 1}`;
  };

  const getConversationSubtitle = (conversation: Conversation): string => {
    const n = conversation.participants.length;

    if (isGlobalConversation(conversation)) {
      return `${n} members`;
    }

    if (!user) {
      return `${n} members`;
    }

    const others = conversation.participants.filter((item) => item.userId !== user.id);
    const treatAsGroup = isGroupConversation(conversation) || others.length > 1;

    if (treatAsGroup) {
      return `${n} members · Group`;
    }

    if (others.length === 1) {
      const online = isPeerOnline(others[0].userId);
      return online ? 'Direct · Online' : 'Direct · Away';
    }

    if (others.length === 0) {
      return 'Only you';
    }

    return `${n} members`;
  };

  const filteredSortedWidgetChats = useMemo(() => {
    if (!widgetMode) {
      return sortedConversations;
    }
    const q = widgetChatSearchQuery.trim().toLowerCase();
    if (!q) {
      return sortedConversations;
    }
    return sortedConversations.filter((c) => {
      const title = getConversationTitle(c).toLowerCase();
      const sub = getConversationSubtitle(c).toLowerCase();
      if (title.includes(q) || sub.includes(q)) {
        return true;
      }
      for (const p of c.participants) {
        const tu = usersById.get(p.userId);
        const name = tu ? userDisplayName(tu).toLowerCase() : (p.user?.name ?? '').toLowerCase();
        const email = (tu?.email ?? p.user?.email ?? '').toLowerCase();
        if (name.includes(q) || email.includes(q) || p.userId.toLowerCase().includes(q)) {
          return true;
        }
      }
      return false;
    });
  }, [widgetMode, sortedConversations, widgetChatSearchQuery, user, usersById]);

  const getSenderLabel = (senderId: string): string => {
    if (senderId === user?.id) {
      return 'You';
    }

    const tenantUser = usersById.get(senderId);
    if (tenantUser) {
      return userDisplayName(tenantUser);
    }

    return senderId.slice(0, 8);
  };

  const findDirectConversation = (targetUserId: string): Conversation | undefined => {
    if (!user) {
      return undefined;
    }

    return conversations.find((conversation) => {
      if (isGlobalConversation(conversation)) {
        return false;
      }

      const participantIds = conversation.participants.map((item) => item.userId);
      return (
        participantIds.length === 2 &&
        participantIds.includes(user.id) &&
        participantIds.includes(targetUserId)
      );
    });
  };

  useEffect(() => {
    if (!socket || !user) {
      return undefined;
    }

    const newSocket = socket;

    const updateUserPresence = (userId: string, isOnline: boolean): void => {
      setTenantUsers((previous) => {
        const index = previous.findIndex((u) => u.id === userId);
        if (index === -1) {
          return previous;
        }
        const current = previous[index];
        if (current.isOnline === isOnline) {
          return previous;
        }
        const next = [...previous];
        next[index] = { ...current, isOnline };
        return next;
      });
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
      setTenantUsers((previous) =>
        previous.map((u) => (Object.prototype.hasOwnProperty.call(map, u.id) ? { ...u, isOnline: !!map[u.id] } : u))
      );
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
      const onlineSet = new Set(ids.filter((id): id is string => typeof id === 'string'));
      setTenantUsers((previous) => previous.map((u) => ({ ...u, isOnline: onlineSet.has(u.id) })));
    };

    newSocket.on('presence_state', onPresenceState);
    newSocket.on('online_users', onOnlineUsersList);

    const onSocketConnect = (): void => {
      setSocketConnected(true);
    };

    const onSocketDisconnect = (): void => {
      setSocketConnected(false);
    };

    newSocket.on('connect', onSocketConnect);
    newSocket.on('disconnect', onSocketDisconnect);

    newSocket.on('message_received', (message: Message) => {
      bumpConversationUpdatedAt(message.conversationId, message.createdAt);

      const isOwnMessage = message.senderId === user?.id;
      if (!isOwnMessage) {
        newSocket.emit('mark_as_delivered', { messageId: message.id }, () => undefined);
      }

      if (message.conversationId === selectedConversationRef.current) {
        upsertMessage(message);
        if (!isOwnMessage) {
          newSocket.emit('mark_as_read', { messageId: message.id }, () => undefined);
        }
        return;
      }

      if (!isOwnMessage) {
        setUnreadByConversation((previous) => ({
          ...previous,
          [message.conversationId]: (previous[message.conversationId] ?? 0) + 1
        }));
      }
    });

    const applyReactionFromSocket = (
      reaction: MessageReaction & { conversationId?: string; reactionType?: string }
    ): void => {
      setMessages((previous) => {
        const convId = reaction.conversationId;
        if (convId && convId !== selectedConversationRef.current) {
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
            } satisfies PublicUser)
        };

        return previous.map((message) => {
          if (message.id !== normalized.messageId) {
            return message;
          }
          const list = message.reactions ?? [];
          const filtered = list.filter((item) => item.userId !== normalized.userId);
          return { ...message, reactions: [...filtered, normalized] };
        });
      });
    };

    newSocket.on('message_reacted', applyReactionFromSocket);
    newSocket.on('reaction_added', applyReactionFromSocket);

    newSocket.on('message_deleted', (payload: { messageId: string; conversationId: string; deletedAt: string }) => {
      if (payload.conversationId !== selectedConversationRef.current) {
        return;
      }

      setMessages((previous) =>
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
    });

    newSocket.on('message_delivered', (receipt: DeliveredReceipt & { conversationId?: string }) => {
      setMessages((previous) =>
        previous.map((message) => {
          if (message.id !== receipt.messageId) {
            return message;
          }

          const filtered = (message.deliveredReceipts ?? []).filter((item) => item.userId !== receipt.userId);
          return { ...message, deliveredReceipts: [...filtered, receipt] };
        })
      );
    });

    newSocket.on('message_read', (receipt: ReadReceipt & { conversationId?: string }) => {
      setMessages((previous) =>
        previous.map((message) => {
          if (message.id !== receipt.messageId) {
            return message;
          }

          const filtered = (message.readReceipts ?? []).filter((item) => item.userId !== receipt.userId);
          return { ...message, readReceipts: [...filtered, receipt] };
        })
      );
    });

    newSocket.on('connect_error', (connectionError) => {
      setError(`Realtime connection failed: ${connectionError.message}`);
    });

    if (newSocket.connected) {
      setSocketConnected(true);
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
      newSocket.off('message_deleted');
      newSocket.off('message_delivered');
      newSocket.off('message_read');
      newSocket.off('connect_error');
      setSocketConnected(false);
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

  const emitWithAck = async <T,>(event: string, payload: unknown): Promise<T> => {
    if (!socket) {
      throw new Error('Socket is not connected');
    }

    return new Promise<T>((resolve, reject) => {
      const timeoutId = window.setTimeout(() => {
        reject(new Error(`Socket event timeout: ${event}`));
      }, SOCKET_ACK_TIMEOUT_MS);

      socket.emit(event, payload, (response: SocketAck<T>) => {
        window.clearTimeout(timeoutId);

        if (!response.ok) {
          reject(new Error(response.error ?? 'Socket error'));
          return;
        }

        resolve(response.data as T);
      });
    });
  };

  useEffect(() => {
    if (!socket || conversations.length === 0) {
      return;
    }

    const joinAllConversations = () => {
      conversations.forEach((conversation) => {
        socket.emit(
          'join_conversation',
          { conversationId: conversation.id },
          (response: SocketAck<{ conversationId: string }>) => {
            if (!response.ok) {
              setError(response.error ?? 'Failed to join conversation');
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

  const refreshConversations = async (): Promise<Conversation[]> => {
    const data = await conversationsApi.listConversations();
    setConversations(data);
    return data;
  };

  const refreshUsers = async (): Promise<void> => {
    const data = await getTenantUsers();
    setTenantUsers(data);
  };

  useEffect(() => {
    if (!token) {
      return;
    }

    const interval = window.setInterval(() => {
      void refreshUsers();
    }, 8000);

    return () => window.clearInterval(interval);
  }, [token]);

  const bootstrapAfterAuth = async (): Promise<void> => {
    const [loadedConversations] = await Promise.all([refreshConversations(), refreshUsers()]);

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
      setSelectedConversationId(initialConversationId);
      setUnreadByConversation((previous) => {
        if (!previous[initialConversationId]) {
          return previous;
        }

        const next = { ...previous };
        delete next[initialConversationId];
        return next;
      });
      const messagesPage = await conversationsApi.getMessagesPage(initialConversationId);
      setMessages(messagesPage.data.map(normalizeMessage));
    }
  };

  useEffect(() => {
    if (!token || !user) {
      return;
    }

    let cancelled = false;
    const bootstrap = async () => {
      try {
        await bootstrapAfterAuth();
      } catch (err) {
        if (cancelled) {
          return;
        }

        setError(err instanceof Error ? err.message : 'Session expired');
        clearSession();
        setConversations([]);
        setTenantUsers([]);
        setSelectedConversationId('');
        setMessages([]);
        setUnreadByConversation({});
        window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
      }
    };

    void bootstrap();

    return () => {
      cancelled = true;
    };
  }, [token, user, clearSession]);

  const handleLogout = (): void => {
    if (socket?.connected && user?.id) {
      socket.emit(CLIENT_GOING_OFFLINE_EVENT, { userId: user.id, reason: 'logout' });
    }
    clearSession();
    setConversations([]);
    setTenantUsers([]);
    setSelectedConversationId('');
    setMessages([]);
    setUnreadByConversation({});
    setText('');
    setError('');
    window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
  };

  const selectConversation = async (conversationId: string): Promise<void> => {
    if (!token) {
      return;
    }

    setError('');
    setSelectedConversationId(conversationId);
    setUnreadByConversation((previous) => {
      if (!previous[conversationId]) {
        return previous;
      }

      const next = { ...previous };
      delete next[conversationId];
      return next;
    });

    try {
      const messagesPage = await conversationsApi.getMessagesPage(conversationId);
      setMessages(messagesPage.data.map(normalizeMessage));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load conversation');
    }
  };

  const widgetBackToInbox = useCallback((): void => {
    setChatHeaderMenuOpen(false);
    setMessageActionsMenuId(null);
    setRailMenuOpen(false);
    setWidgetInboxMenuOpen(false);
    setWidgetRailPane('chats');
    setSelectedConversationId('');
  }, []);

  const openDirectChat = async (target: TenantUser): Promise<void> => {
    if (!token || !user) {
      return;
    }

    setError('');
    setOpeningDirectUserId(target.id);

    try {
      const existing = findDirectConversation(target.id);
      if (existing) {
        if (widgetMode) {
          setWidgetRailPane('chats');
        }
        await selectConversation(existing.id);
        return;
      }

      const createdConversation = await conversationsApi.createDirectConversation(target.id);
      await refreshConversations();
      if (widgetMode) {
        setWidgetRailPane('chats');
      }
      await selectConversation(createdConversation.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to open direct chat');
    } finally {
      setOpeningDirectUserId('');
    }
  };

  const openGroupModal = (): void => {
    setGroupModalError('');
    setGroupTitle('');
    setGroupSelectedUserIds([]);
    setGroupPickerSearch('');
    setGroupModalOpen(true);
  };

  const addUserToGroupSelection = (userId: string): void => {
    setGroupSelectedUserIds((previous) => (previous.includes(userId) ? previous : [...previous, userId]));
  };

  const removeUserFromGroupSelection = (userId: string): void => {
    setGroupSelectedUserIds((previous) => previous.filter((id) => id !== userId));
  };

  const handleCreateGroup = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (!token || !user) {
      return;
    }

    const title = groupTitle.trim();
    if (title.length < 1 || title.length > 120) {
      setGroupModalError('Group name must be 1–120 characters.');
      return;
    }
    if (groupSelectedUserIds.length < 2) {
      setGroupModalError('Add at least two other people to the group.');
      return;
    }

    setCreatingGroup(true);
    setGroupModalError('');

    try {
      const participantIds = [...new Set([user.id, ...groupSelectedUserIds])];
      const created = await conversationsApi.createGroupConversation(title, participantIds);
      setGroupModalOpen(false);
      setGroupTitle('');
      setGroupSelectedUserIds([]);
      setGroupPickerSearch('');
      await refreshConversations();
      await selectConversation(created.id);
    } catch (err) {
      setGroupModalError(err instanceof Error ? err.message : 'Could not create group');
    } finally {
      setCreatingGroup(false);
    }
  };

  const openEditGroupModal = (): void => {
    if (!selectedConversation || !isGroupConversation(selectedConversation)) {
      return;
    }
    setEditGroupError('');
    setEditGroupConversationId(selectedConversation.id);
    setEditGroupTitle(selectedConversation.title?.trim() ?? '');
    const ids = selectedConversation.participants.map((p) => p.userId);
    setEditGroupParticipantIds([...ids]);
    editGroupInitialIdsRef.current = [...ids];
    setEditGroupPickerSearch('');
    setEditGroupModalOpen(true);
    setChatHeaderMenuOpen(false);
  };

  const addEditGroupMember = (userId: string): void => {
    setEditGroupParticipantIds((previous) => (previous.includes(userId) ? previous : [...previous, userId]));
  };

  const removeEditGroupMember = (userId: string): void => {
    if (userId === user?.id) {
      return;
    }
    setEditGroupParticipantIds((previous) => {
      if (previous.length <= 2) {
        return previous;
      }
      return previous.filter((id) => id !== userId);
    });
  };

  const handleSaveEditGroup = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (!token || !user) {
      return;
    }
    const convId = editGroupConversationId;
    const title = editGroupTitle.trim();
    if (title.length < 1 || title.length > 120) {
      setEditGroupError('Group name must be 1–120 characters.');
      return;
    }
    const initialIds = editGroupInitialIdsRef.current;
    const initial = new Set(initialIds);
    const current = new Set(editGroupParticipantIds);
    const removedSelf = initial.has(user.id) && !current.has(user.id);

    if (!removedSelf && editGroupParticipantIds.length < 2) {
      setEditGroupError('A group needs at least two members.');
      return;
    }

    setEditGroupSaving(true);
    setEditGroupError('');

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

      setEditGroupModalOpen(false);
      await refreshConversations();
      if (removedSelf) {
        setSelectedConversationId('');
        setMessages([]);
      } else {
        await selectConversation(convId);
      }
    } catch (err) {
      setEditGroupError(err instanceof Error ? err.message : 'Failed to update group');
    } finally {
      setEditGroupSaving(false);
    }
  };

  const handleLeaveGroup = async (): Promise<void> => {
    if (!token || !user) {
      return;
    }
    const convId = editGroupConversationId;
    if (!convId) {
      return;
    }
    if (!window.confirm('Leave this group? You will need a new invite to rejoin.')) {
      return;
    }
    setEditGroupSaving(true);
    setEditGroupError('');
    try {
      await conversationsApi.removeConversationParticipant(convId, user.id);
      setEditGroupModalOpen(false);
      await refreshConversations();
      setSelectedConversationId('');
      setMessages([]);
    } catch (err) {
      setEditGroupError(err instanceof Error ? err.message : 'Could not leave group');
    } finally {
      setEditGroupSaving(false);
    }
  };

  const handleDeleteSelectedConversation = async (): Promise<void> => {
    if (!token || !selectedConversation) {
      return;
    }
    if (isGlobalConversation(selectedConversation)) {
      window.alert('This channel cannot be deleted here.');
      setChatHeaderMenuOpen(false);
      return;
    }
    const label = getConversationTitle(selectedConversation);
    if (!window.confirm(`Delete “${label}”? This removes the chat for you.`)) {
      return;
    }
    setDeletingConversation(true);
    setChatHeaderMenuOpen(false);
    setError('');
    try {
      const id = selectedConversation.id;
      await conversationsApi.deleteConversationById(id);
      await refreshConversations();
      setSelectedConversationId('');
      setMessages([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete conversation');
    } finally {
      setDeletingConversation(false);
    }
  };

  const handleSendText = async (): Promise<void> => {
    if (!selectedConversationId || !text.trim()) {
      return;
    }

    try {
      const message = await emitWithAck<Message>('send_message', {
        conversationId: selectedConversationId,
        type: 'TEXT' as MessageType,
        content: text.trim()
      });
      upsertMessage(message);
      bumpConversationUpdatedAt(selectedConversationId, message.createdAt);
      setText('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message');
    }
  };

  const handleSendUploadedMessage = async (file: File, type: MessageType): Promise<void> => {
    if (!token || !selectedConversationId) {
      return;
    }

    try {
      const uploaded = await uploadFileRequest(file);
      const message = await emitWithAck<Message>('send_message', {
        conversationId: selectedConversationId,
        type,
        content: uploaded.url
      });
      upsertMessage(message);
      bumpConversationUpdatedAt(selectedConversationId, message.createdAt);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    }
  };

  const revertOptimisticReaction = (messageId: string, optimisticId: string): void => {
    setMessages((previous) =>
      previous.map((m) => {
        if (m.id !== messageId) {
          return m;
        }
        const list = (m.reactions ?? []).filter((r) => r.id !== optimisticId);
        return { ...m, reactions: list };
      })
    );
  };

  /** Persists via REST when the server exposes it; otherwise uses the realtime socket (server should still store in DB). */
  const handleReact = (messageId: string, emoji: string): void => {
    if (!user || !selectedConversationId) {
      return;
    }

    setError('');
    setMessageActionsMenuId(null);
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

    setMessages((previous) =>
      previous.map((m) => {
        if (m.id !== messageId) {
          return m;
        }
        const list = m.reactions ?? [];
        const filtered = list.filter((r) => r.userId !== user.id);
        return { ...m, reactions: [...filtered, optimisticReaction] };
      })
    );

    void (async (): Promise<void> => {
      if (token) {
        try {
          const updated = await conversationsApi.addMessageReaction(conversationId, messageId, emoji);
          if (updated && typeof updated === 'object' && 'id' in updated && updated.id === messageId) {
            setMessages((previous) =>
              previous.map((m) => (m.id === messageId ? normalizeMessage(updated) : m))
            );
            return;
          }
        } catch (err) {
          const skipSocket =
            err instanceof ApiError && [404, 405, 501].includes(err.status);
          if (!skipSocket) {
            revertOptimisticReaction(messageId, optimisticId);
            setError(err instanceof Error ? err.message : 'Failed to react');
            return;
          }
        }
      }

      if (!socket?.connected) {
        revertOptimisticReaction(messageId, optimisticId);
        setError('Not connected — cannot send reaction');
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
            revertOptimisticReaction(messageId, optimisticId);
            setError(response.error ?? 'Failed to react');
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
            setMessages((previous) =>
              previous.map((m) => (m.id === messageId ? normalizeMessage(data as Message) : m))
            );
          }
        }
      );
    })();
  };

  const handleDelete = async (messageId: string): Promise<void> => {
    try {
      await emitWithAck('delete_message', { messageId });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete message');
    }
  };

  const handleMarkRead = async (messageId: string): Promise<void> => {
    try {
      await emitWithAck('mark_as_read', { messageId });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to mark as read');
    }
  };

  const handleTranscribeVoiceMessage = async (message: Message): Promise<void> => {
    if (!token) {
      setError('Sign in required');
      return;
    }
    const id = message.id;
    patchMessageSpeechUi(id, { loading: 'transcribe', error: undefined });
    try {
      const blob = await fetchMediaBlob(message.content, token);
      const out = await transcribeSpeechRequest(blob, { filename: 'message.webm' });
      const text = out.data?.text ?? '';
      patchMessageSpeechUi(id, { loading: undefined, transcript: text });
    } catch (err) {
      patchMessageSpeechUi(id, {
        loading: undefined,
        error: err instanceof Error ? err.message : 'Transcription failed'
      });
    }
  };

  const handleTranslateForMessage = async (
    message: Message,
    sourceText: string,
    targetLanguage: string
  ): Promise<void> => {
    if (!token) {
      setError('Sign in required');
      return;
    }
    if (!sourceText.trim()) {
      return;
    }
    const id = message.id;
    patchMessageSpeechUi(id, { loading: 'translate', error: undefined });
    try {
      const out = await translateTextRequest({
        text: sourceText,
        targetLanguage
      });
      const translated = out.data?.translatedText ?? '';
      patchMessageSpeechUi(id, { loading: undefined, translated });
    } catch (err) {
      patchMessageSpeechUi(id, {
        loading: undefined,
        error: err instanceof Error ? err.message : 'Translation failed'
      });
    }
  };

  const startRecording = async (): Promise<void> => {
    if (!token || !selectedConversationId || isRecording) {
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
      setError('Browser does not support audio recording');
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
        await handleSendUploadedMessage(file, 'VOICE');
      };

      recorder.start();
      mediaRecorderRef.current = recorder;
      setIsRecording(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start recording');
    }
  };

  const finishRecording = (): void => {
    const recorder = mediaRecorderRef.current;
    if (!recorder || recorder.state === 'inactive') {
      setIsRecording(false);
      return;
    }
    discardRecordingRef.current = false;
    recorder.stop();
    setIsRecording(false);
  };

  const cancelRecording = (): void => {
    const recorder = mediaRecorderRef.current;
    if (!recorder || recorder.state === 'inactive') {
      audioStreamRef.current?.getTracks().forEach((track) => track.stop());
      audioStreamRef.current = null;
      mediaRecorderRef.current = null;
      setIsRecording(false);
      return;
    }
    discardRecordingRef.current = true;
    recorder.stop();
    setIsRecording(false);
  };

  if (!sessionHydrated) {
    return shellWrap(
      <div className={`auth-shell${widgetMode ? ' auth-shell--widget' : ''}`}>
        <div className="auth-card">
          <h1>Healthcare Messenger</h1>
          <p className="auth-subtitle">Restoring your session...</p>
        </div>
      </div>
    );
  }

  if (!token || !user) {
    return shellWrap(
      <div className={`auth-shell${widgetMode ? ' auth-shell--widget' : ''}`}>
        <div className="auth-card">
          <h1>Healthcare Messenger</h1>
          <p className="auth-subtitle">
            Register uses <code>tenantId</code>, name, and email. Login uses a UUID <code>tenantId</code> and email,
            matching server Zod schemas.
          </p>

          {widgetMissingTenant && (
            <p className="error-banner">
              Missing tenant configuration. Set <code>tenantId</code> in the embed URL or{' '}
              <code>window.__HEALTHCHAT_WIDGET_CONFIG__</code>.
            </p>
          )}

          <AuthForm
            widgetMode={widgetMode}
            widgetConfig={widgetConfig ?? undefined}
            widgetMissingTenant={widgetMissingTenant}
          />
        </div>
      </div>
    );
  }

  return shellWrap(
    <div
      className={`messenger-shell${widgetMode ? ' messenger-shell--widget' : ''}${
        widgetMode && selectedConversationId ? ' messenger-shell--widget-chat' : ''
      }`}
    >
      <aside
        className={`left-rail${widgetMode ? ' left-rail--widget-full' : ''}`}
        aria-hidden={widgetMode ? Boolean(selectedConversationId) : undefined}
      >
        {widgetMode && widgetRailPane === 'people' ? (
          <div className="left-header left-header--widget-people">
            <button
              type="button"
              className="widget-people-back"
              onClick={() => {
                setWidgetRailPane('chats');
                setPeopleSearchQuery('');
              }}
              aria-label="Back to chats"
            >
              ←
            </button>
            <div className="left-header-main">
              <h2>People</h2>
              <p className="widget-people-subtitle">Everyone in your organization</p>
            </div>
          </div>
        ) : !widgetMode ? (
          <div className="left-header">
            <AvatarWithPresence online={socketConnected}>
              <div className="avatar-pill">{userInitials(user)}</div>
            </AvatarWithPresence>
            <div className="left-header-main">
              <h2>Chats</h2>
              <p>{userDisplayName(user)}</p>
              <span className="socket-presence-caption">
                <PresenceDot online={socketConnected} title={socketConnected ? 'Realtime connected' : 'Realtime disconnected'} />
                {socketConnected ? 'Live' : 'Offline'}
              </span>
            </div>
          </div>
        ) : null}

        {!widgetMode && (
          <div className="left-rail-toolbar">
            <button
              type="button"
              className="refresh-btn"
              onClick={() => {
                void refreshConversations();
                void refreshUsers();
              }}
            >
              Refresh
            </button>
            <div className="rail-menu-wrap" ref={railMenuRef}>
              <button
                type="button"
                className="rail-menu-btn"
                aria-expanded={railMenuOpen}
                aria-haspopup="menu"
                onClick={() => setRailMenuOpen((open) => !open)}
              >
                Menu ▾
              </button>
              {railMenuOpen && (
                <div className="rail-menu-dropdown" role="menu">
                  <button
                    type="button"
                    role="menuitem"
                    className="rail-menu-item"
                    onClick={() => {
                      setRailMenuOpen(false);
                      openGroupModal();
                    }}
                  >
                    New group
                  </button>
                </div>
              )}
            </div>
            <button type="button" className="logout-btn" onClick={handleLogout}>
              Logout
            </button>
          </div>
        )}

        <div className={`left-rail-scroll${widgetMode ? ' left-rail-scroll--widget-order' : ''}`}>
          {!widgetMode && (
            <section className="quick-chat" aria-label="Search people and start a chat">
              <h3>Start a chat</h3>
              <label className="quick-chat-search-label">
                <span className="visually-hidden">Search by name, email, or status</span>
                <input
                  className="quick-chat-search"
                  type="search"
                  value={peopleSearchQuery}
                  onChange={(event) => setPeopleSearchQuery(event.target.value)}
                  placeholder="Search to start a new chat…"
                  autoComplete="off"
                  spellCheck={false}
                  aria-label="Search people in your tenant"
                />
              </label>
              <div className="quick-list">
                {sortedTenantPeers.length === 0 && (
                  <span className="muted-text">No other users in this tenant yet.</span>
                )}
                {peersWithoutDirectChat.length > 0 && filteredPeersForNewChat.length === 0 && (
                  <span className="muted-text">No one matches &quot;{peopleSearchQuery.trim()}&quot;. Try another keyword.</span>
                )}
                {filteredPeersForNewChat.map((tenantUser) => (
                  <button
                    key={tenantUser.id}
                    type="button"
                    className="quick-item"
                    onClick={() => void openDirectChat(tenantUser)}
                    disabled={openingDirectUserId === tenantUser.id}
                    aria-label={`Open chat with ${userDisplayName(tenantUser)}`}
                  >
                    <AvatarWithPresence online={tenantUser.isOnline}>
                      <div className="avatar-mini">{userInitials(tenantUser)}</div>
                    </AvatarWithPresence>
                    <div className="quick-user-meta">
                      <strong>{userDisplayName(tenantUser)}</strong>
                      <span>
                        {tenantUser.status ?? '—'} · {tenantUser.isOnline ? 'Active' : 'Away'}
                      </span>
                      <span className="quick-user-email">{tenantUser.email}</span>
                    </div>
                    <span className="quick-item-action">
                      {openingDirectUserId === tenantUser.id ? 'Opening…' : 'Chat →'}
                    </span>
                  </button>
                ))}
              </div>
            </section>
          )}

          {widgetMode && widgetRailPane === 'people' && (
            <section className="quick-chat" aria-label="All people in your tenant">
              <label className="quick-chat-search-label">
                <span className="visually-hidden">Search people by name or email</span>
                <input
                  className="quick-chat-search"
                  type="search"
                  value={peopleSearchQuery}
                  onChange={(event) => setPeopleSearchQuery(event.target.value)}
                  placeholder="Search people…"
                  autoComplete="off"
                  spellCheck={false}
                  aria-label="Search all people"
                />
              </label>
              <div className="quick-list">
                {sortedTenantPeers.length === 0 && (
                  <span className="muted-text">No other users in this tenant yet.</span>
                )}
                {sortedTenantPeers.length > 0 && widgetAllPeopleFiltered.length === 0 && (
                  <span className="muted-text">No one matches &quot;{peopleSearchQuery.trim()}&quot;.</span>
                )}
                {widgetAllPeopleFiltered.map((tenantUser) => (
                  <button
                    key={tenantUser.id}
                    type="button"
                    className="quick-item"
                    onClick={() => void openDirectChat(tenantUser)}
                    disabled={openingDirectUserId === tenantUser.id}
                    aria-label={`Open chat with ${userDisplayName(tenantUser)}`}
                  >
                    <AvatarWithPresence online={tenantUser.isOnline}>
                      <div className="avatar-mini">{userInitials(tenantUser)}</div>
                    </AvatarWithPresence>
                    <div className="quick-user-meta">
                      <strong>{userDisplayName(tenantUser)}</strong>
                      <span>
                        {tenantUser.status ?? '—'} · {tenantUser.isOnline ? 'Active' : 'Away'}
                      </span>
                      <span className="quick-user-email">{tenantUser.email}</span>
                    </div>
                    <span className="quick-item-action">
                      {openingDirectUserId === tenantUser.id ? 'Opening…' : 'Chat →'}
                    </span>
                  </button>
                ))}
              </div>
            </section>
          )}

          {(!widgetMode || widgetRailPane === 'chats') && (
          <section className="conversation-list" aria-label="Your conversations">
            {widgetMode ? (
              <h2 className="widget-overview-chats-title">Chats</h2>
            ) : (
              <h3 className="conversation-list-heading">Chats</h3>
            )}
            {widgetMode && (
              <div className="widget-chats-search-row">
                <div className="widget-chats-menu-wrap" ref={widgetInboxMenuRef}>
                  <button
                    type="button"
                    className="chat-header-menu-btn widget-chats-overflow-btn"
                    aria-expanded={widgetInboxMenuOpen}
                    aria-haspopup="menu"
                    aria-label="More options"
                    onClick={() => setWidgetInboxMenuOpen((open) => !open)}
                  >
                    ⋮
                  </button>
                  {widgetInboxMenuOpen && (
                    <div className="rail-menu-dropdown rail-menu-dropdown--widget-chats-row" role="menu">
                      <button
                        type="button"
                        role="menuitem"
                        className="rail-menu-item rail-menu-item--widget-suggest"
                        onClick={() => {
                          setWidgetInboxMenuOpen(false);
                          setPeopleSearchQuery('');
                          setWidgetRailPane('people');
                        }}
                      >
                        Suggested people
                      </button>
                      <button
                        type="button"
                        role="menuitem"
                        className="rail-menu-item rail-menu-item--widget-suggest"
                        onClick={() => {
                          setWidgetInboxMenuOpen(false);
                          openGroupModal();
                        }}
                      >
                        New group
                      </button>
                    </div>
                  )}
                </div>
                <label className="widget-chats-search-label">
                  <span className="visually-hidden">Search your chats</span>
                  <input
                    className="quick-chat-search widget-chats-search-input"
                    type="search"
                    value={widgetChatSearchQuery}
                    onChange={(event) => setWidgetChatSearchQuery(event.target.value)}
                    placeholder="Search chats…"
                    autoComplete="off"
                    spellCheck={false}
                    aria-label="Search chats"
                  />
                </label>
              </div>
            )}
            {(widgetMode ? filteredSortedWidgetChats : sortedConversations).map((conversation) => {
            const unreadCount = unreadByConversation[conversation.id] ?? 0;
            const listOtherId = getSingleOtherParticipantId(conversation);
            const listAvatar = (
              <div className="avatar-mini">
                {isGlobalConversation(conversation)
                  ? 'ALL'
                  : userInitials(conversation.participants[0]?.user ?? { name: null, email: '?' })}
              </div>
            );

            const convTitle = getConversationTitle(conversation);

            return (
              <button
                key={conversation.id}
                type="button"
                className={`conversation-item ${conversation.id === selectedConversationId ? 'active' : ''}${
                  unreadCount > 0 ? ' conversation-item--unread' : ''
                }`}
                aria-label={
                  unreadCount > 0
                    ? `${convTitle}, ${unreadCount} unread message${unreadCount === 1 ? '' : 's'}`
                    : convTitle
                }
                onClick={() => void selectConversation(conversation.id)}
              >
                {listOtherId !== undefined && !isGlobalConversation(conversation) ? (
                  <AvatarWithPresence online={isPeerOnline(listOtherId)}>{listAvatar}</AvatarWithPresence>
                ) : (
                  listAvatar
                )}
                <div className="conversation-meta">
                  <div className="conversation-meta-top">
                    <strong>{convTitle}</strong>
                    {unreadCount > 0 && (
                      <span className="unread-badge" aria-hidden>
                        {unreadCount > 99 ? '99+' : unreadCount}
                      </span>
                    )}
                  </div>
                  <span>{getConversationSubtitle(conversation)}</span>
                </div>
              </button>
            );
          })}
          {widgetMode &&
            widgetRailPane === 'chats' &&
            filteredSortedWidgetChats.length === 0 &&
            sortedConversations.length > 0 && (
              <p className="muted-text widget-chats-empty-hint">No chats match your search.</p>
            )}
          {widgetMode && widgetRailPane === 'chats' && sortedConversations.length === 0 && (
            <p className="muted-text widget-chats-empty-hint">
              No chats yet. Tap ⋮ and choose Suggested people to browse everyone.
            </p>
          )}
          </section>
          )}
        </div>
      </aside>

      <main
        className={`chat-stage${widgetMode ? ' chat-stage--widget' : ''}`}
        aria-hidden={widgetMode ? !selectedConversationId : undefined}
      >
        {!selectedConversation ? (
          <div className="blank-chat">
            {widgetMode ? 'Pick a chat from the list or search above.' : 'Select a conversation.'}
          </div>
        ) : (
          <>
            <header className="chat-header">
              <div className="chat-header-main">
                {widgetMode && (
                  <button
                    type="button"
                    className="chat-header-back"
                    onClick={widgetBackToInbox}
                    aria-label="Back to chat list"
                  >
                    ←
                  </button>
                )}
                {selectedDirectPeerId !== undefined ? (
                  <AvatarWithPresence online={isPeerOnline(selectedDirectPeerId)}>
                    <div className="avatar-pill">
                      {isGlobalConversation(selectedConversation)
                        ? 'ALL'
                        : userInitials(selectedConversation.participants[0]?.user ?? { name: null, email: '?' })}
                    </div>
                  </AvatarWithPresence>
                ) : (
                  <div className="avatar-pill">
                    {isGlobalConversation(selectedConversation)
                      ? 'ALL'
                      : userInitials(selectedConversation.participants[0]?.user ?? { name: null, email: '?' })}
                  </div>
                )}
                <div className="chat-header-titles">
                  <h3>{getConversationTitle(selectedConversation)}</h3>
                  <p>{getConversationSubtitle(selectedConversation)}</p>
                </div>
              </div>
              <div className="chat-header-menu-wrap" ref={chatHeaderMenuRef}>
                <button
                  type="button"
                  className="chat-header-menu-btn"
                  aria-expanded={chatHeaderMenuOpen}
                  aria-haspopup="menu"
                  aria-label="Chat options"
                  onClick={() => setChatHeaderMenuOpen((open) => !open)}
                >
                  ⋮
                </button>
                {chatHeaderMenuOpen && (
                  <div className="rail-menu-dropdown chat-header-dropdown" role="menu">
                    {isGroupConversation(selectedConversation) && (
                      <button type="button" role="menuitem" className="rail-menu-item" onClick={() => openEditGroupModal()}>
                        Edit group
                      </button>
                    )}
                    {!isGlobalConversation(selectedConversation) && (
                      <button
                        type="button"
                        role="menuitem"
                        className="rail-menu-item rail-menu-item-danger"
                        disabled={deletingConversation}
                        onClick={() => void handleDeleteSelectedConversation()}
                      >
                        {deletingConversation ? 'Deleting…' : 'Delete conversation'}
                      </button>
                    )}
                  </div>
                )}
              </div>
            </header>

            <section className="message-scroller" ref={messageScrollerRef}>
              {messages.map((message) => {
                const isMine = message.senderId === user.id;
                const status = isMine ? getDeliveryStatus(message) : null;
                const showSenderLabel =
                  selectedConversation != null &&
                  (isGroupConversation(selectedConversation) || isGlobalConversation(selectedConversation));
                const menuOpen = messageActionsMenuId === message.id;
                const speechUi = messageSpeechUi[message.id];

                return (
                  <div key={message.id} className={`message-row-outer ${isMine ? 'mine' : 'theirs'}`}>
                    <div
                      className={`message-cluster ${isMine ? 'mine' : 'theirs'}${menuOpen ? ' message-cluster--menu-open' : ''}`}
                    >
                      <div className="message-content-stack">
                        {!message.deletedAt && (
                          <div className="message-hover-actions">
                            <div className="message-reaction-strip" role="toolbar" aria-label="Quick reactions">
                              {QUICK_REACTION_EMOJIS.map((emoji) => (
                                <button
                                  key={emoji}
                                  type="button"
                                  className="message-reaction-strip-btn"
                                  aria-label={`React ${emoji}`}
                                  onClick={() => handleReact(message.id, emoji)}
                                >
                                  {emoji}
                                </button>
                              ))}
                            </div>
                            <div className="message-more-wrap" data-message-menu-root={message.id}>
                              <button
                                type="button"
                                className="message-more-btn"
                                aria-expanded={menuOpen}
                                aria-haspopup="menu"
                                aria-label="Message actions"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setMessageActionsMenuId((current) => (current === message.id ? null : message.id));
                                }}
                              >
                                ⋮
                              </button>
                              {menuOpen && (
                                <div className="message-actions-dropdown" role="menu">
                                  <div className="message-actions-reactions" role="none">
                                    <span className="message-actions-reactions-label">React</span>
                                    <div className="message-actions-reactions-row" role="group">
                                      {QUICK_REACTION_EMOJIS.map((emoji) => (
                                        <button
                                          key={emoji}
                                          type="button"
                                          role="menuitem"
                                          className="message-actions-emoji-btn"
                                          aria-label={`React ${emoji}`}
                                          onClick={() => handleReact(message.id, emoji)}
                                        >
                                          {emoji}
                                        </button>
                                      ))}
                                    </div>
                                  </div>
                                  {!isMine && (
                                    <button
                                      type="button"
                                      role="menuitem"
                                      className="message-actions-item"
                                      onClick={() => {
                                        setMessageActionsMenuId(null);
                                        void handleMarkRead(message.id);
                                      }}
                                    >
                                      Mark as read
                                    </button>
                                  )}
                                  {isMine && (
                                    <button
                                      type="button"
                                      role="menuitem"
                                      className="message-actions-item message-actions-item-danger"
                                      onClick={() => {
                                        setMessageActionsMenuId(null);
                                        void handleDelete(message.id);
                                      }}
                                    >
                                      Delete
                                    </button>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        <article className={`message-bubble ${isMine ? 'mine' : 'theirs'}`}>
                          {showSenderLabel && (
                            <div className="message-label">{getSenderLabel(message.senderId)}</div>
                          )}
                          {message.deletedAt ? (
                            <em className="deleted">Message deleted</em>
                          ) : getMessageType(message) === 'IMAGE' ? (
                            <img src={toAbsoluteMediaUrl(message.content)} alt="Uploaded" />
                          ) : getMessageType(message) === 'VOICE' ? (
                            <>
                              <audio controls src={toAbsoluteMediaUrl(message.content)} />
                              <div className="message-msgr-translation">
                                {!speechUi?.transcript ? (
                                  <>
                                    <button
                                      type="button"
                                      className="message-msgr-link"
                                      disabled={speechUi?.loading === 'transcribe'}
                                      onClick={() => void handleTranscribeVoiceMessage(message)}
                                    >
                                      {speechUi?.loading === 'transcribe' ? 'Transcribing…' : 'Transcribe'}
                                    </button>
                                    {speechUi?.error && !speechUi?.transcript ? (
                                      <p className="message-msgr-error" role="alert">
                                        {speechUi.error}
                                      </p>
                                    ) : null}
                                  </>
                                ) : (
                                  <>
                                    <p className="message-msgr-transcript">{speechUi.transcript}</p>
                                    {speechUi.translated ? (
                                      <>
                                        <div className="message-msgr-divider" aria-hidden />
                                        <p className="message-msgr-meta">
                                          Translation · {translateLangLabel(speechUi.targetLang ?? 'en')}
                                        </p>
                                        <p className="message-msgr-translation-body" aria-live="polite">
                                          {speechUi.translated}
                                        </p>
                                        <button
                                          type="button"
                                          className="message-msgr-link"
                                          onClick={() =>
                                            patchMessageSpeechUi(message.id, {
                                              translated: undefined,
                                              error: undefined,
                                              translateToolsOpen: false
                                            })
                                          }
                                        >
                                          See original
                                        </button>
                                      </>
                                    ) : speechUi.translateToolsOpen ? (
                                      <div className="message-msgr-tools">
                                        <label className="visually-hidden" htmlFor={`trg-voice-${message.id}`}>
                                          Language
                                        </label>
                                        <select
                                          id={`trg-voice-${message.id}`}
                                          className="message-msgr-select"
                                          value={speechUi.targetLang ?? 'en'}
                                          onChange={(event) =>
                                            patchMessageSpeechUi(message.id, { targetLang: event.target.value })
                                          }
                                        >
                                          {TRANSLATE_TARGET_LANGS.map((lang) => (
                                            <option key={lang.code} value={lang.code}>
                                              {lang.label}
                                            </option>
                                          ))}
                                        </select>
                                        <button
                                          type="button"
                                          className="message-msgr-link"
                                          disabled={speechUi.loading === 'translate'}
                                          onClick={() =>
                                            void handleTranslateForMessage(
                                              message,
                                              speechUi.transcript ?? '',
                                              speechUi.targetLang ?? 'en'
                                            )
                                          }
                                        >
                                          {speechUi.loading === 'translate' ? 'Translating…' : 'See translation'}
                                        </button>
                                      </div>
                                    ) : (
                                      <button
                                        type="button"
                                        className="message-msgr-link"
                                        onClick={() =>
                                          patchMessageSpeechUi(message.id, { translateToolsOpen: true })
                                        }
                                      >
                                        See translation
                                      </button>
                                    )}
                                    {speechUi.error && speechUi.transcript && !speechUi.translated ? (
                                      <p className="message-msgr-error" role="alert">
                                        {speechUi.error}
                                      </p>
                                    ) : null}
                                  </>
                                )}
                              </div>
                            </>
                          ) : (
                            <>
                              <p>{message.content}</p>
                              <div className="message-msgr-translation">
                                {speechUi?.translated ? (
                                  <>
                                    <div className="message-msgr-divider" aria-hidden />
                                    <p className="message-msgr-meta">
                                      Translation · {translateLangLabel(speechUi?.targetLang ?? 'en')}
                                    </p>
                                    <p className="message-msgr-translation-body" aria-live="polite">
                                      {speechUi.translated}
                                    </p>
                                    <button
                                      type="button"
                                      className="message-msgr-link"
                                      onClick={() =>
                                        patchMessageSpeechUi(message.id, {
                                          translated: undefined,
                                          error: undefined,
                                          translateToolsOpen: false
                                        })
                                      }
                                    >
                                      See original
                                    </button>
                                  </>
                                ) : speechUi?.translateToolsOpen ? (
                                  <>
                                    <div className="message-msgr-tools">
                                      <label className="visually-hidden" htmlFor={`trg-text-${message.id}`}>
                                        Language
                                      </label>
                                      <select
                                        id={`trg-text-${message.id}`}
                                        className="message-msgr-select"
                                        value={speechUi?.targetLang ?? 'en'}
                                        onChange={(event) =>
                                          patchMessageSpeechUi(message.id, { targetLang: event.target.value })
                                        }
                                      >
                                        {TRANSLATE_TARGET_LANGS.map((lang) => (
                                          <option key={lang.code} value={lang.code}>
                                            {lang.label}
                                          </option>
                                        ))}
                                      </select>
                                      <button
                                        type="button"
                                        className="message-msgr-link"
                                        disabled={speechUi?.loading === 'translate'}
                                        onClick={() =>
                                          void handleTranslateForMessage(
                                            message,
                                            message.content,
                                            speechUi?.targetLang ?? 'en'
                                          )
                                        }
                                      >
                                        {speechUi?.loading === 'translate' ? 'Translating…' : 'See translation'}
                                      </button>
                                    </div>
                                    {speechUi?.error ? (
                                      <p className="message-msgr-error" role="alert">
                                        {speechUi.error}
                                      </p>
                                    ) : null}
                                  </>
                                ) : (
                                  <button
                                    type="button"
                                    className="message-msgr-link"
                                    onClick={() =>
                                      patchMessageSpeechUi(message.id, { translateToolsOpen: true })
                                    }
                                  >
                                    See translation
                                  </button>
                                )}
                              </div>
                            </>
                          )}

                          <div className="message-info">
                            <span>{new Date(message.createdAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</span>
                            {status && (
                              <span className={`message-status ${status}`} aria-label={`Message ${status}`}>
                                {status === 'sent' ? '✓' : '✓✓'}
                              </span>
                            )}
                          </div>
                        </article>

                        {!message.deletedAt && (message.reactions ?? []).length > 0 && (
                          <div className="message-reactions message-reactions-below" aria-label="Reactions">
                            {summarizeReactions(message.reactions ?? [], user.id).map((group) => (
                              <span
                                key={group.emoji}
                                className={`message-reaction-chip ${group.mine ? 'message-reaction-chip--mine' : ''}`}
                                title={group.title}
                              >
                                <span className="message-reaction-emoji">{group.emoji}</span>
                                {group.count > 1 && (
                                  <span className="message-reaction-count">{group.count}</span>
                                )}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </section>

            {isRecording ? (
              <footer className="recording-bar" role="status" aria-live="polite">
                <button type="button" className="recording-bar-cancel" onClick={cancelRecording}>
                  Cancel
                </button>
                <div className="recording-bar-center">
                  <span className="recording-bar-dot" aria-hidden />
                  <div className="recording-bars" aria-hidden>
                    <span />
                    <span />
                    <span />
                    <span />
                    <span />
                  </div>
                  <div className="recording-bar-text">
                    <span className="recording-bar-title">Recording</span>
                    <span className="recording-bar-time">{formatRecordingDuration(recordingDurationMs)}</span>
                  </div>
                </div>
                <button
                  type="button"
                  className="recording-bar-done"
                  title="Send voice message"
                  aria-label="Send voice message"
                  onClick={finishRecording}
                >
                  <IconCheckSend />
                  <span className="recording-bar-done-label">Send</span>
                </button>
              </footer>
            ) : (
              <footer className="composer-bar">
                <input
                  className="composer-input"
                  value={text}
                  onChange={(event) => setText(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' && !event.shiftKey) {
                      event.preventDefault();
                      void handleSendText();
                    }
                  }}
                  placeholder="Type a message… (Enter to send)"
                  aria-label="Message text"
                />
                <div className="composer-actions" role="group" aria-label="Attachments and send">
                  <label className="composer-icon-btn" title="Attach image">
                    <IconImage />
                    <span className="visually-hidden">Attach image</span>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(event) => {
                        const file = event.target.files?.[0];
                        if (file) {
                          void handleSendUploadedMessage(file, 'IMAGE');
                        }
                        event.target.value = '';
                      }}
                    />
                  </label>
                  <label className="composer-icon-btn" title="Attach audio file">
                    <IconAttach />
                    <span className="visually-hidden">Attach audio file</span>
                    <input
                      type="file"
                      accept="audio/*"
                      onChange={(event) => {
                        const file = event.target.files?.[0];
                        if (file) {
                          void handleSendUploadedMessage(file, 'VOICE');
                        }
                        event.target.value = '';
                      }}
                    />
                  </label>
                  <button
                    type="button"
                    className="composer-icon-btn composer-record-btn"
                    title="Record voice message"
                    aria-label="Record voice message"
                    onClick={() => void startRecording()}
                  >
                    <IconRecord />
                  </button>
                  <button
                    type="button"
                    className="composer-icon-btn composer-send-btn"
                    title="Send"
                    aria-label="Send message"
                    disabled={!text.trim()}
                    onClick={() => void handleSendText()}
                  >
                    <IconSend />
                  </button>
                </div>
              </footer>
            )}
          </>
        )}

        {error && <p className="error-banner inline">{error}</p>}
      </main>

      {groupModalOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={() => {
            if (!creatingGroup) {
              setGroupModalOpen(false);
            }
          }}
        >
          <div
            className="modal-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="group-modal-title"
            onClick={(event) => event.stopPropagation()}
          >
            <h2 id="group-modal-title" className="modal-title">
              New group
            </h2>
            <p className="modal-subtitle">Choose a name and at least two members. You will be added automatically.</p>

            <form className="group-modal-form" onSubmit={(event) => void handleCreateGroup(event)}>
              <label className="modal-field">
                <span className="modal-label">Group name</span>
                <input
                  className="modal-input"
                  value={groupTitle}
                  onChange={(event) => setGroupTitle(event.target.value)}
                  placeholder="e.g. Care team"
                  maxLength={120}
                  required
                  autoFocus
                />
              </label>

              <div className="modal-field">
                <span className="modal-label">Members ({groupSelectedUserIds.length} selected)</span>
                <div className="group-member-chips">
                  {groupSelectedUserIds.length === 0 && (
                    <span className="muted-text">No members yet — add from the list below.</span>
                  )}
                  {groupSelectedUserIds.map((id) => {
                    const peer = usersById.get(id);
                    if (!peer) {
                      return null;
                    }
                    return (
                      <span key={id} className="group-member-chip">
                        <span>{userDisplayName(peer)}</span>
                        <button
                          type="button"
                          className="group-member-chip-remove"
                          onClick={() => removeUserFromGroupSelection(id)}
                          disabled={creatingGroup}
                          aria-label={`Remove ${userDisplayName(peer)}`}
                        >
                          ×
                        </button>
                      </span>
                    );
                  })}
                </div>
              </div>

              <label className="modal-field">
                <span className="modal-label">Add people</span>
                <input
                  className="modal-input"
                  type="search"
                  value={groupPickerSearch}
                  onChange={(event) => setGroupPickerSearch(event.target.value)}
                  placeholder="Search by name or email…"
                  autoComplete="off"
                />
              </label>

              <div className="group-picker-list" role="list">
                {sortedTenantPeers.length === 0 ? (
                  <p className="muted-text">No other users in your tenant.</p>
                ) : filteredGroupPickerPeers.length === 0 ? (
                  <p className="muted-text">Everyone matching your search is already added.</p>
                ) : (
                  filteredGroupPickerPeers.map((peer) => (
                    <div key={peer.id} className="group-picker-row" role="listitem">
                      <div className="group-picker-meta">
                        <strong>{userDisplayName(peer)}</strong>
                        <span className="group-picker-email">{peer.email}</span>
                      </div>
                      <button
                        type="button"
                        className="group-picker-add"
                        onClick={() => addUserToGroupSelection(peer.id)}
                        disabled={creatingGroup}
                      >
                        Add
                      </button>
                    </div>
                  ))
                )}
              </div>

              {groupModalError && <p className="modal-error">{groupModalError}</p>}

              <div className="modal-actions">
                <button
                  type="button"
                  className="modal-btn modal-btn-secondary"
                  onClick={() => {
                    if (!creatingGroup) {
                      setGroupModalOpen(false);
                    }
                  }}
                >
                  Cancel
                </button>
                <button type="submit" className="modal-btn modal-btn-primary" disabled={creatingGroup}>
                  {creatingGroup ? 'Creating…' : 'Create group'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {editGroupModalOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={() => {
            if (!editGroupSaving) {
              setEditGroupModalOpen(false);
            }
          }}
        >
          <div
            className="modal-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="edit-group-modal-title"
            onClick={(event) => event.stopPropagation()}
          >
            <h2 id="edit-group-modal-title" className="modal-title">
              Edit group
            </h2>
            <p className="modal-subtitle">
              Rename the group, add people, or remove other members. Use <strong>Leave group</strong> below to exit yourself.
            </p>

            <form className="group-modal-form" onSubmit={(event) => void handleSaveEditGroup(event)}>
              <label className="modal-field">
                <span className="modal-label">Group name</span>
                <input
                  className="modal-input"
                  value={editGroupTitle}
                  onChange={(event) => setEditGroupTitle(event.target.value)}
                  maxLength={120}
                  required
                  autoFocus
                />
              </label>

              <div className="modal-field">
                <span className="modal-label">Members ({editGroupParticipantIds.length})</span>
                <div className="group-member-chips">
                  {editGroupParticipantIds.map((id) => (
                    <span key={id} className={`group-member-chip ${id === user?.id ? 'group-member-chip--self' : ''}`}>
                      <span>
                        {displayNameForParticipantId(id)}
                        {id === user?.id ? ' (you)' : ''}
                      </span>
                      {id !== user?.id && (
                        <button
                          type="button"
                          className="group-member-chip-remove"
                          onClick={() => removeEditGroupMember(id)}
                          disabled={editGroupSaving || editGroupParticipantIds.length <= 2}
                          aria-label={`Remove ${displayNameForParticipantId(id)}`}
                        >
                          ×
                        </button>
                      )}
                    </span>
                  ))}
                </div>
              </div>

              <label className="modal-field">
                <span className="modal-label">Add people</span>
                <input
                  className="modal-input"
                  type="search"
                  value={editGroupPickerSearch}
                  onChange={(event) => setEditGroupPickerSearch(event.target.value)}
                  placeholder="Search by name or email…"
                  autoComplete="off"
                />
              </label>

              <div className="group-picker-list" role="list">
                {filteredEditGroupPickerPeers.length === 0 ? (
                  <p className="muted-text">No one left to add, or no matches.</p>
                ) : (
                  filteredEditGroupPickerPeers.map((peer) => (
                    <div key={peer.id} className="group-picker-row" role="listitem">
                      <div className="group-picker-meta">
                        <strong>{userDisplayName(peer)}</strong>
                        <span className="group-picker-email">{peer.email}</span>
                      </div>
                      <button
                        type="button"
                        className="group-picker-add"
                        onClick={() => addEditGroupMember(peer.id)}
                        disabled={editGroupSaving}
                      >
                        Add
                      </button>
                    </div>
                  ))
                )}
              </div>

              {editGroupError && <p className="modal-error">{editGroupError}</p>}

              <div className="modal-leave-row">
                <button
                  type="button"
                  className="modal-btn modal-btn-leave"
                  disabled={editGroupSaving}
                  onClick={() => void handleLeaveGroup()}
                >
                  Leave group
                </button>
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="modal-btn modal-btn-secondary"
                  onClick={() => {
                    if (!editGroupSaving) {
                      setEditGroupModalOpen(false);
                    }
                  }}
                >
                  Cancel
                </button>
                <button type="submit" className="modal-btn modal-btn-primary" disabled={editGroupSaving}>
                  {editGroupSaving ? 'Saving…' : 'Save changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
