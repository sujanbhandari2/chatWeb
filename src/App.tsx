import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { createConversation, getConversations, getMessages, getUsers, login, register, uploadFile } from './api/client';
import {
  AuthUser,
  Conversation,
  DeliveredReceipt,
  Message,
  MessageReaction,
  MessageType,
  ReadReceipt,
  TenantUser
} from './types/chat';

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL ?? 'http://localhost:4000';
const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:4000/api';
const BACKEND_ORIGIN = API_URL.replace(/\/api\/?$/, '');
const SESSION_STORAGE_KEY = 'healthchat.session';
const SELECTED_CONVERSATION_STORAGE_KEY = 'healthchat.selectedConversation';

type SocketAck<T> = { ok: boolean; data?: T; error?: string };
const SOCKET_ACK_TIMEOUT_MS = 8000;
type DeliveryStatus = 'sent' | 'delivered' | 'seen';

const toAbsoluteMediaUrl = (url: string): string => {
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return url;
  }

  return `${BACKEND_ORIGIN}${url}`;
};

const displayName = (username: string): string => {
  return username
    .split(/[_-]/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
};

const initials = (username: string): string => {
  const chunks = displayName(username).split(' ').filter(Boolean);
  return (chunks[0]?.[0] ?? 'U') + (chunks[1]?.[0] ?? chunks[0]?.[1] ?? '');
};

const getDeliveryStatus = (message: Message): DeliveryStatus => {
  const hasSeen = message.readReceipts.some((item) => item.userId !== message.senderId);
  if (hasSeen) {
    return 'seen';
  }

  const hasDelivered = message.deliveredReceipts.some((item) => item.userId !== message.senderId);
  if (hasDelivered) {
    return 'delivered';
  }

  return 'sent';
};

export default function App() {
  const [token, setToken] = useState<string>('');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [tenantUsers, setTenantUsers] = useState<TenantUser[]>([]);
  const [selectedConversationId, setSelectedConversationId] = useState<string>('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [text, setText] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [openingDirectUserId, setOpeningDirectUserId] = useState<string>('');
  const [isRecording, setIsRecording] = useState<boolean>(false);
  const [socket, setSocket] = useState<Socket | null>(null);
  const [unreadByConversation, setUnreadByConversation] = useState<Record<string, number>>({});
  const [sessionHydrated, setSessionHydrated] = useState<boolean>(false);

  const selectedConversationRef = useRef<string>('');
  const messageScrollerRef = useRef<HTMLElement | null>(null);
  const lastAutoScrollKeyRef = useRef<string>('');
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const audioStreamRef = useRef<MediaStream | null>(null);

  useEffect(() => {
    selectedConversationRef.current = selectedConversationId;
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
      const rawSession = window.localStorage.getItem(SESSION_STORAGE_KEY);
      if (rawSession) {
        const parsed = JSON.parse(rawSession) as { token: string; user: AuthUser };
        if (parsed.token && parsed.user?.id) {
          setToken(parsed.token);
          setUser(parsed.user);
        }
      }
    } catch {
      window.localStorage.removeItem(SESSION_STORAGE_KEY);
    } finally {
      setSessionHydrated(true);
    }
  }, []);

  useEffect(() => {
    if (!sessionHydrated) {
      return;
    }

    try {
      if (token && user) {
        window.localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ token, user }));
      } else {
        window.localStorage.removeItem(SESSION_STORAGE_KEY);
      }
    } catch {
      window.localStorage.removeItem(SESSION_STORAGE_KEY);
    }
  }, [token, user, sessionHydrated]);

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

  const authFormDefaults = useMemo(
    () => ({
      username: '',
      password: ''
    }),
    []
  );

  const [authForm, setAuthForm] = useState(authFormDefaults);

  const usersById = useMemo(() => {
    return new Map(tenantUsers.map((item) => [item.id, item]));
  }, [tenantUsers]);

  const selectedConversation = useMemo(
    () => conversations.find((conversation) => conversation.id === selectedConversationId) ?? null,
    [conversations, selectedConversationId]
  );

  const onlineUsers = useMemo(
    () => tenantUsers.filter((tenantUser) => tenantUser.isOnline && tenantUser.id !== user?.id),
    [tenantUsers, user?.id]
  );

  const upsertMessage = (incoming: Message): void => {
    setMessages((previous) => {
      const existingIndex = previous.findIndex((message) => message.id === incoming.id);
      if (existingIndex === -1) {
        return [...previous, incoming];
      }

      const next = [...previous];
      next[existingIndex] = incoming;
      return next;
    });
  };

  const getConversationTitle = (conversation: Conversation): string => {
    if (conversation.isGlobal) {
      return 'System Broadcast (All Users)';
    }

    if (!user) {
      return 'Conversation';
    }

    const others = conversation.participants.filter((item) => item.userId !== user.id);

    if (others.length === 0) {
      return 'Just You';
    }

    if (others.length === 1) {
      return displayName(others[0].user.username);
    }

    return `${displayName(others[0].user.username)} + ${others.length - 1}`;
  };

  const getConversationSubtitle = (conversation: Conversation): string => {
    if (conversation.isGlobal) {
      return `${conversation.participants.length} registered users`;
    }

    const roles = conversation.participants.map((item) => item.user.role);
    return `${conversation.participants.length} people · ${roles.join(', ')}`;
  };

  const getSenderLabel = (senderId: string): string => {
    if (senderId === user?.id) {
      return 'You';
    }

    return displayName(usersById.get(senderId)?.username ?? senderId.slice(0, 8));
  };

  const findDirectConversation = (targetUserId: string): Conversation | undefined => {
    if (!user) {
      return undefined;
    }

    return conversations.find((conversation) => {
      if (conversation.isGlobal) {
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
    if (!token) {
      return;
    }

    const newSocket = io(SOCKET_URL, {
      auth: { token },
      transports: ['websocket']
    });

    newSocket.on('message_received', (message: Message) => {
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

    newSocket.on('message_reacted', (reaction: MessageReaction & { conversationId: string }) => {
      if (reaction.conversationId !== selectedConversationRef.current) {
        return;
      }

      setMessages((previous) =>
        previous.map((message) => {
          if (message.id !== reaction.messageId) {
            return message;
          }

          const filtered = message.reactions.filter((item) => item.userId !== reaction.userId);
          return { ...message, reactions: [...filtered, reaction] };
        })
      );
    });

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

          const filtered = message.deliveredReceipts.filter((item) => item.userId !== receipt.userId);
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

          const filtered = message.readReceipts.filter((item) => item.userId !== receipt.userId);
          return { ...message, readReceipts: [...filtered, receipt] };
        })
      );
    });

    newSocket.on('connect_error', (connectionError) => {
      setError(`Realtime connection failed: ${connectionError.message}`);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
      setSocket(null);
    };
  }, [token, user?.id]);

  useEffect(() => {
    if (!socket || !selectedConversationId || !user) {
      return;
    }

    messages.forEach((message) => {
      if (message.senderId === user.id || message.deletedAt) {
        return;
      }

      if (!message.deliveredReceipts.some((item) => item.userId === user.id)) {
        socket.emit('mark_as_delivered', { messageId: message.id }, () => undefined);
      }

      if (!message.readReceipts.some((item) => item.userId === user.id)) {
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

  const refreshConversations = async (authToken: string): Promise<Conversation[]> => {
    const data = await getConversations(authToken);
    setConversations(data);
    return data;
  };

  const refreshUsers = async (authToken: string): Promise<void> => {
    const data = await getUsers(authToken);
    setTenantUsers(data);
  };

  useEffect(() => {
    if (!token) {
      return;
    }

    const interval = window.setInterval(() => {
      void refreshUsers(token);
    }, 10000);

    return () => window.clearInterval(interval);
  }, [token]);

  const bootstrapAfterAuth = async (authToken: string): Promise<void> => {
    const [loadedConversations] = await Promise.all([
      refreshConversations(authToken),
      refreshUsers(authToken)
    ]);

    const persistedConversationId = window.localStorage.getItem(SELECTED_CONVERSATION_STORAGE_KEY);
    const hasPersistedConversation =
      !!persistedConversationId &&
      loadedConversations.some((conversation) => conversation.id === persistedConversationId);
    const globalConversation = loadedConversations.find((conversation) => conversation.isGlobal);
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
      const loadedMessages = await getMessages(authToken, initialConversationId);
      setMessages(loadedMessages);
    }
  };

  useEffect(() => {
    if (!token || !user) {
      return;
    }

    let cancelled = false;
    const bootstrap = async () => {
      try {
        await bootstrapAfterAuth(token);
      } catch (err) {
        if (cancelled) {
          return;
        }

        setError(err instanceof Error ? err.message : 'Session expired');
        setToken('');
        setUser(null);
        setConversations([]);
        setTenantUsers([]);
        setSelectedConversationId('');
        setMessages([]);
        setUnreadByConversation({});
        window.localStorage.removeItem(SESSION_STORAGE_KEY);
        window.localStorage.removeItem(SELECTED_CONVERSATION_STORAGE_KEY);
      }
    };

    void bootstrap();

    return () => {
      cancelled = true;
    };
  }, [token, user]);

  const handleAuth = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const response =
        authMode === 'register'
          ? await register({ username: authForm.username, password: authForm.password })
          : await login({ username: authForm.username, password: authForm.password });

      setToken(response.token);
      setUser(response.user);
      setAuthForm(authFormDefaults);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = (): void => {
    socket?.disconnect();
    setToken('');
    setUser(null);
    setConversations([]);
    setTenantUsers([]);
    setSelectedConversationId('');
    setMessages([]);
    setUnreadByConversation({});
    setText('');
    setError('');
    window.localStorage.removeItem(SESSION_STORAGE_KEY);
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
      const loadedMessages = await getMessages(token, conversationId);
      setMessages(loadedMessages);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load conversation');
    }
  };

  const openDirectChat = async (target: TenantUser): Promise<void> => {
    if (!token || !user) {
      return;
    }

    setError('');
    setOpeningDirectUserId(target.id);

    try {
      const existing = findDirectConversation(target.id);
      if (existing) {
        await selectConversation(existing.id);
        return;
      }

      const createdConversation = await createConversation(token, [target.id]);
      await refreshConversations(token);
      await selectConversation(createdConversation.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to open direct chat');
    } finally {
      setOpeningDirectUserId('');
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
      const uploaded = await uploadFile(token, file);
      const message = await emitWithAck<Message>('send_message', {
        conversationId: selectedConversationId,
        type,
        content: uploaded.url
      });
      upsertMessage(message);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    }
  };

  const handleReact = async (messageId: string, reactionType: string): Promise<void> => {
    try {
      await emitWithAck('react_to_message', { messageId, reactionType });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to react');
    }
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

  const startRecording = async (): Promise<void> => {
    if (!token || !selectedConversationId || isRecording) {
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
      setError('Browser does not support audio recording');
      return;
    }

    try {
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
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        const file = new File([audioBlob], `voice-${Date.now()}.webm`, { type: 'audio/webm' });
        await handleSendUploadedMessage(file, 'VOICE');

        audioStreamRef.current?.getTracks().forEach((track) => track.stop());
        audioStreamRef.current = null;
      };

      recorder.start();
      mediaRecorderRef.current = recorder;
      setIsRecording(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start recording');
    }
  };

  const stopRecording = (): void => {
    if (!mediaRecorderRef.current || mediaRecorderRef.current.state === 'inactive') {
      return;
    }

    mediaRecorderRef.current.stop();
    setIsRecording(false);
  };

  if (!sessionHydrated) {
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <h1>Healthcare Messenger</h1>
          <p className="auth-subtitle">Restoring your session...</p>
        </div>
      </div>
    );
  }

  if (!token || !user) {
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <h1>Healthcare Messenger</h1>
          <p className="auth-subtitle">Register or login with a unique username and password</p>

          <div className="auth-mode-switch">
            <button
              className={authMode === 'login' ? 'active' : ''}
              onClick={() => setAuthMode('login')}
              type="button"
            >
              Login
            </button>
            <button
              className={authMode === 'register' ? 'active' : ''}
              onClick={() => setAuthMode('register')}
              type="button"
            >
              Register
            </button>
          </div>

          <form onSubmit={handleAuth} className="auth-form">
            <input
              value={authForm.username}
              onChange={(event) => setAuthForm((prev) => ({ ...prev, username: event.target.value }))}
              placeholder="Username"
              required
            />
            <input
              value={authForm.password}
              onChange={(event) => setAuthForm((prev) => ({ ...prev, password: event.target.value }))}
              placeholder="Password"
              type="password"
              required
            />
            <button type="submit" disabled={isLoading}>
              {isLoading
                ? authMode === 'register'
                  ? 'Creating account...'
                  : 'Signing in...'
                : authMode === 'register'
                  ? 'Register'
                  : 'Login'}
            </button>
          </form>

          {error && <p className="error-banner">{error}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className="messenger-shell">
      <aside className="left-rail">
        <div className="left-header">
          <div className="avatar-pill">{initials(user.username)}</div>
          <div>
            <h2>Chats</h2>
            <p>{displayName(user.username)}</p>
          </div>
        </div>

        <button
          className="refresh-btn"
          onClick={() => {
            void refreshConversations(token);
            void refreshUsers(token);
          }}
        >
          Refresh
        </button>
        <button className="logout-btn" onClick={handleLogout}>
          Logout
        </button>

        <section className="quick-chat">
          <h3>Online Users</h3>
          <p>{onlineUsers.length} currently logged in</p>
          <div className="quick-list">
            {onlineUsers.length === 0 && <span className="muted-text">No other users online right now.</span>}
            {onlineUsers.map((tenantUser) => (
              <div key={tenantUser.id} className="quick-item">
                <div className="avatar-mini">{initials(tenantUser.username)}</div>
                <div className="quick-user-meta">
                  <strong>{displayName(tenantUser.username)}</strong>
                  <span>{tenantUser.role}</span>
                </div>
                <button
                  onClick={() => void openDirectChat(tenantUser)}
                  disabled={openingDirectUserId === tenantUser.id}
                >
                  {openingDirectUserId === tenantUser.id ? 'Opening...' : 'Chat'}
                </button>
              </div>
            ))}
          </div>
        </section>

        <section className="conversation-list">
          {conversations.map((conversation) => {
            const unreadCount = unreadByConversation[conversation.id] ?? 0;

            return (
              <button
                key={conversation.id}
                className={`conversation-item ${conversation.id === selectedConversationId ? 'active' : ''}`}
                onClick={() => void selectConversation(conversation.id)}
              >
                <div className="avatar-mini">
                  {conversation.isGlobal ? 'ALL' : initials(conversation.participants[0]?.user.username ?? 'u')}
                </div>
                <div className="conversation-meta">
                  <div className="conversation-meta-top">
                    <strong>{getConversationTitle(conversation)}</strong>
                    {unreadCount > 0 && <span className="unread-badge">{unreadCount > 99 ? '99+' : unreadCount}</span>}
                  </div>
                  <span>{getConversationSubtitle(conversation)}</span>
                </div>
              </button>
            );
          })}
        </section>
      </aside>

      <main className="chat-stage">
        {!selectedConversation ? (
          <div className="blank-chat">Select a conversation.</div>
        ) : (
          <>
            <header className="chat-header">
              <div className="avatar-pill">{selectedConversation.isGlobal ? 'ALL' : initials(selectedConversation.participants[0]?.user.username ?? 'u')}</div>
              <div>
                <h3>{getConversationTitle(selectedConversation)}</h3>
                <p>{getConversationSubtitle(selectedConversation)}</p>
              </div>
            </header>

            <section className="message-scroller" ref={messageScrollerRef}>
              {messages.map((message) => {
                const isMine = message.senderId === user.id;
                const status = isMine ? getDeliveryStatus(message) : null;

                return (
                  <article key={message.id} className={`message-row ${isMine ? 'mine' : 'theirs'}`}>
                    <div className={`message-bubble ${isMine ? 'mine' : 'theirs'}`}>
                      <div className="message-label">{getSenderLabel(message.senderId)}</div>
                      {message.deletedAt ? (
                        <em className="deleted">Message deleted</em>
                      ) : message.type === 'IMAGE' ? (
                        <img src={toAbsoluteMediaUrl(message.content)} alt="Uploaded" />
                      ) : message.type === 'VOICE' ? (
                        <audio controls src={toAbsoluteMediaUrl(message.content)} />
                      ) : (
                        <p>{message.content}</p>
                      )}

                      <div className="message-info">
                        <span>{new Date(message.createdAt).toLocaleTimeString()}</span>
                        {status && (
                          <span className={`message-status ${status}`} aria-label={`Message ${status}`}>
                            {status === 'sent' ? '✓' : '✓✓'}
                          </span>
                        )}
                      </div>

                      <div className="message-tools">
                        <button onClick={() => void handleReact(message.id, '👍')}>👍</button>
                        <button onClick={() => void handleReact(message.id, '❤️')}>❤️</button>
                        {!isMine && <button onClick={() => void handleMarkRead(message.id)}>Seen</button>}
                        {(isMine || user.role === 'ADMIN') && (
                          <button onClick={() => void handleDelete(message.id)}>Delete</button>
                        )}
                      </div>
                    </div>
                  </article>
                );
              })}
            </section>

            <footer className="composer-bar">
              <input value={text} onChange={(event) => setText(event.target.value)} placeholder="Type a message..." />
              <button onClick={() => void handleSendText()}>Send</button>
              <label className="attach-btn">
                Image
                <input
                  type="file"
                  accept="image/*"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) {
                      void handleSendUploadedMessage(file, 'IMAGE');
                    }
                  }}
                />
              </label>
              <label className="attach-btn">
                Voice
                <input
                  type="file"
                  accept="audio/*"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) {
                      void handleSendUploadedMessage(file, 'VOICE');
                    }
                  }}
                />
              </label>
              {!isRecording ? (
                <button onClick={() => void startRecording()}>Record</button>
              ) : (
                <button onClick={stopRecording}>Stop</button>
              )}
            </footer>
          </>
        )}

        {error && <p className="error-banner inline">{error}</p>}
      </main>
    </div>
  );
}
