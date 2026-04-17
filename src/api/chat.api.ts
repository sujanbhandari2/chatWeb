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
  const companyId = String(raw.companyId ?? raw.company_id ?? raw.tenantId ?? raw.tenant_id ?? '');
  return { ...(raw as unknown as Conversation), companyId };
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

export const createConversation = (
  body: {
    isGlobal?: boolean;
    isGroupChat?: boolean;
    creatorUserId?: string;
    participantIds?: string[];
  } = {}
): Promise<Conversation> =>
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
  const created = await createConversation({});
  const convId = created.id;
  if (!convId) {
    throw new Error('Invalid conversation response');
  }
  await addConversationParticipant(convId, currentUserId);
  await addConversationParticipant(convId, targetUserId);
  const list = await listConversations(currentUserId);
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
    isGroupChat: true,
    creatorUserId,
    ...(extras.length > 0 ? { participantIds: extras } : {})
  }).then(normalizeConversationFromApi);
}

/** `GET /api/v1/chat/clients` — company ids where the client has chat profiles. */
export const listChatClients = (): Promise<unknown[]> =>
  apiService.get<unknown>(API_PATHS.CHAT.CLIENTS).then((raw) => unwrapArray<unknown>(raw));

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
