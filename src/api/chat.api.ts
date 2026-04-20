import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { Conversation, Message, MessagesPage } from '../types/chat';
import { normalizeMessage } from '../utils/chat.utils';

function unwrapArray<T>(raw: unknown): T[] {
  if (Array.isArray(raw)) {
    return raw as T[];
  }
  if (raw && typeof raw === 'object' && 'data' in raw && Array.isArray((raw as { data: unknown }).data)) {
    return (raw as { data: T[] }).data;
  }
  return [];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function normalizeConversationFromApi(raw: unknown): Conversation {
  if (!isRecord(raw)) {
    return raw as Conversation;
  }
  const pickIso = (...candidates: unknown[]): string => {
    for (const c of candidates) {
      if (typeof c === 'string' && c.trim() !== '') {
        return c.trim();
      }
    }
    return '';
  };
  const companyId = String(raw.companyId ?? raw.company_id ?? raw.tenantId ?? raw.tenant_id ?? '');
  const updatedAt = pickIso(
    raw.updatedAt,
    raw.updated_at,
    raw.lastMessageAt,
    raw.last_message_at,
    raw.createdAt,
    raw.created_at
  );
  const createdAt = pickIso(raw.createdAt, raw.created_at, updatedAt);
  const id = String(raw.id ?? raw.uuid ?? raw.conversation_id ?? raw.conversationId ?? '').trim();
  const participantsRaw = raw.participants;
  const participants = Array.isArray(participantsRaw)
    ? (participantsRaw as Conversation['participants'])
    : [];
  const base = { ...(raw as unknown as Conversation) };
  return {
    ...base,
    id: id || String(base.id ?? ''),
    participants: participants.length > 0 ? participants : base.participants ?? [],
    companyId,
    ...(updatedAt ? { updatedAt } : {}),
    ...(createdAt ? { createdAt } : {})
  };
}

function normalizeMessagesPage(raw: unknown): MessagesPage {
  const r = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const legacyPag = r.pagination as Record<string, unknown> | undefined;
  const items = Array.isArray(r.items)
    ? (r.items as Message[])
    : Array.isArray(r.data)
      ? (r.data as Message[])
      : [];
  const page = Number(r.page ?? legacyPag?.page ?? 1) || 1;
  const pageSize = Number(r.pageSize ?? legacyPag?.pageSize ?? 20) || 20;
  const total = Number(r.total ?? legacyPag?.total ?? 0) || 0;
  const totalPages =
    Number(legacyPag?.totalPages) > 0
      ? Number(legacyPag?.totalPages)
      : Math.max(1, Math.ceil(total / pageSize));
  return {
    data: items,
    pagination: { page, pageSize, total, totalPages }
  };
}

function conversationMessagesPath(conversationId: string): string {
  return `${API_PATHS.CHAT.CONVERSATIONS}/${encodeURIComponent(conversationId)}/messages`;
}

function conversationParticipantsPath(conversationId: string): string {
  return `${API_PATHS.CHAT.CONVERSATIONS}/${encodeURIComponent(conversationId)}/participants`;
}

export const listConversations = (forUserId: string): Promise<Conversation[]> =>
  apiService
    .get<unknown>(`${API_PATHS.CHAT.CONVERSATIONS}?${new URLSearchParams({ forUserId })}`)
    .then((raw) => unwrapArray<unknown>(raw).map(normalizeConversationFromApi));

/** Chat API `CreateConversationDto` — DIRECT/SUPPORT may omit `participantIds` and add via `POST .../participants`. */
export type CreateChatConversationBody =
  | { type: 'DIRECT'; participantIds?: string[] }
  | { type: 'GROUP'; creatorUserId: string; participantIds?: string[] }
  | { type: 'SUPPORT'; participantIds?: string[] };

export const createConversation = (body: CreateChatConversationBody): Promise<Conversation> =>
  apiService.post<unknown>(API_PATHS.CHAT.CONVERSATIONS, body).then(normalizeConversationFromApi);

export const addConversationParticipant = (
  conversationId: string,
  userId: string,
  actorUserId?: string
): Promise<unknown> =>
  apiService.post(conversationParticipantsPath(conversationId), {
    userId,
    ...(actorUserId ? { actorUserId } : {})
  });

export const deleteConversationById = (conversationId: string): Promise<void> =>
  apiService.delete<void>(`${API_PATHS.CHAT.CONVERSATIONS}/${encodeURIComponent(conversationId)}`);

export const updateConversationById = (
  conversationId: string,
  body: { title: string }
): Promise<Conversation> =>
  apiService
    .patch<unknown>(`${API_PATHS.CHAT.CONVERSATIONS}/${encodeURIComponent(conversationId)}`, body)
    .then(normalizeConversationFromApi);

export const addConversationParticipants = async (
  conversationId: string,
  userIds: string[],
  actorUserId?: string
): Promise<Conversation> => {
  for (const userId of userIds) {
    await addConversationParticipant(conversationId, userId, actorUserId);
  }
  const primary = userIds[0];
  if (!primary) {
    throw new Error('No participant to resolve conversation');
  }
  const list = await listConversations(primary);
  const found = list.find((c) => c.id === conversationId);
  if (!found) {
    throw new Error('Conversation not found after adding participants');
  }
  return found;
};

export const removeConversationParticipant = (conversationId: string, userId: string): Promise<void> =>
  apiService.delete<void>(
    `${API_PATHS.CHAT.CONVERSATIONS}/${encodeURIComponent(conversationId)}/participants/${encodeURIComponent(userId)}`
  );

export const getMessagesPage = (conversationId: string, page = 1, pageSize = 50): Promise<MessagesPage> => {
  const query = new URLSearchParams({
    page: String(page),
    pageSize: String(Math.min(Math.max(pageSize, 1), 100))
  });
  return apiService
    .get<unknown>(`${conversationMessagesPath(conversationId)}?${query}`)
    .then((raw) => {
      const page = normalizeMessagesPage(raw);
      return {
        ...page,
        data: page.data.map((m) => normalizeMessage(m))
      };
    });
};

export const postRestMessage = (conversationId: string, body: { type: string; content: string; senderId: string }) =>
  apiService.post<Message>(conversationMessagesPath(conversationId), body);

export const addMessageReaction = (
  conversationId: string,
  messageId: string,
  emoji: string
): Promise<Message> =>
  apiService
    .post<Message | { data: Message }>(
      `${conversationMessagesPath(conversationId)}/${encodeURIComponent(messageId)}/reactions`,
      { emoji, reactionType: emoji }
    )
    .then((raw) => {
      if (
        raw &&
        typeof raw === 'object' &&
        'data' in raw &&
        raw.data &&
        typeof (raw as { data: Message }).data.id === 'string'
      ) {
        return (raw as { data: Message }).data;
      }
      return raw as Message;
    });

export async function createDirectConversation(
  targetUserId: string,
  currentUserId: string
): Promise<Conversation> {
  const a = targetUserId.trim();
  const b = currentUserId.trim();
  if (!a || !b) {
    throw new Error('Direct conversation requires two chat user ids');
  }
  const created = await createConversation({ type: 'DIRECT' });
  const convId = String(created.id ?? '').trim();
  if (!convId) {
    throw new Error('Invalid conversation response: missing id');
  }
  await addConversationParticipant(convId, b);
  await addConversationParticipant(convId, a);
  const list = await listConversations(b);
  return list.find((c) => c.id === convId) ?? created;
}

export async function createGroupConversation(
  _title: string,
  participantIds: string[]
): Promise<Conversation> {
  const creatorUserId = participantIds[0];
  if (!creatorUserId) {
    throw new Error('Group requires a creator');
  }
  const extras = participantIds.slice(1);
  return createConversation({
    type: 'GROUP',
    creatorUserId,
    ...(extras.length > 0 ? { participantIds: extras } : {})
  });
}

/** `GET /api/v1/chat/tenant` — tenant context for the API key (e.g. `{ tenantId }`). */
export const getChatTenant = (): Promise<unknown> => apiService.get<unknown>(API_PATHS.CHAT.TENANT);

export const listChatUsers = (): Promise<unknown[]> =>
  apiService.get<unknown>(API_PATHS.CHAT.USERS).then((raw) => {
    const list = unwrapArray<unknown>(raw);
    return list;
  });

export type RegisterPushTokenBody = {
  token: string;
  platform: 'IOS' | 'ANDROID' | 'WEB';
  deviceId?: string;
};

/** `POST /api/v1/chat/users/:userId/push-tokens` */
export const registerChatUserPushToken = (userId: string, body: RegisterPushTokenBody): Promise<unknown> =>
  apiService.post<unknown>(
    `${API_PATHS.CHAT.USERS}/${encodeURIComponent(userId)}/push-tokens`,
    body
  );
