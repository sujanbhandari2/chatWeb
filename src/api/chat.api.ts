import type { AxiosRequestConfig } from 'axios';
import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { Conversation, Message, MessagesPage } from '../types/chat';

function unwrapArray<T>(raw: unknown): T[] {
  if (Array.isArray(raw)) {
    return raw as T[];
  }
  if (raw && typeof raw === 'object' && 'data' in raw && Array.isArray((raw as { data: unknown }).data)) {
    return (raw as { data: T[] }).data;
  }
  return [];
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
    .then((raw) => unwrapArray<Conversation>(raw));

export const createConversation = (body: { isGlobal?: boolean } = {}): Promise<Conversation> =>
  apiService.post<Conversation>(API_PATHS.CHAT.CONVERSATIONS, body);

export const addConversationParticipant = (conversationId: string, userId: string): Promise<unknown> =>
  apiService.post(conversationParticipantsPath(conversationId), { userId });

export const deleteConversationById = (conversationId: string): Promise<void> =>
  apiService.delete<void>(`${API_PATHS.CHAT.CONVERSATIONS}/${encodeURIComponent(conversationId)}`);

export const updateConversationById = (
  conversationId: string,
  body: { title: string }
): Promise<Conversation> =>
  apiService.patch<Conversation>(
    `${API_PATHS.CHAT.CONVERSATIONS}/${encodeURIComponent(conversationId)}`,
    body
  );

export const addConversationParticipants = async (
  conversationId: string,
  userIds: string[]
): Promise<Conversation> => {
  for (const userId of userIds) {
    await addConversationParticipant(conversationId, userId);
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
  return apiService.get<MessagesPage>(`${conversationMessagesPath(conversationId)}?${query}`);
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
  const created = await createConversation({});
  const convId = created.id;
  if (!convId) {
    throw new Error('Invalid conversation response');
  }
  for (const userId of participantIds) {
    await addConversationParticipant(convId, userId);
  }
  const primary = participantIds[0];
  if (!primary) {
    return created;
  }
  const list = await listConversations(primary);
  return list.find((c) => c.id === convId) ?? created;
}

export type ChatUserRole = 'CLIENT' | 'AGENT' | 'ADMIN';

export type CreateChatUserBody = {
  role: ChatUserRole;
  email: string;
  username: string;
  name?: string;
};

export const createChatUser = (
  body: CreateChatUserBody,
  config?: AxiosRequestConfig
): Promise<unknown> => apiService.post<unknown>(API_PATHS.CHAT.USERS, body, config);

export const listChatUsers = (): Promise<unknown[]> =>
  apiService.get<unknown>(API_PATHS.CHAT.USERS).then((raw) => {
    const list = unwrapArray<unknown>(raw);
    return list;
  });
