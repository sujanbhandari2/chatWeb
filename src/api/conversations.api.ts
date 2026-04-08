import { API_PATHS } from '../constants/api.constants';
import { apiService } from '../lib/api-service';
import type { Conversation, Message, MessagesPage } from '../types/chat';

export const listConversations = (): Promise<Conversation[]> =>
  apiService.get<{ data: Conversation[] }>(API_PATHS.CONVERSATIONS).then((r) => r.data);

export const createConversation = (participantIds: string[]): Promise<Conversation> =>
  apiService.post<Conversation>(API_PATHS.CONVERSATIONS, { participantIds });

export const createDirectConversation = (userId: string): Promise<Conversation> =>
  apiService.post<Conversation>(`${API_PATHS.CONVERSATIONS}/direct`, { userId });

export const createGroupConversation = (title: string, participantIds: string[]): Promise<Conversation> =>
  apiService.post<Conversation>(`${API_PATHS.CONVERSATIONS}/group`, { title, participantIds });

export const deleteConversationById = (conversationId: string): Promise<void> =>
  apiService.delete<void>(`${API_PATHS.CONVERSATIONS}/${conversationId}`);

export const updateConversationById = (
  conversationId: string,
  body: { title: string }
): Promise<Conversation> => apiService.patch<Conversation>(`${API_PATHS.CONVERSATIONS}/${conversationId}`, body);

export const addConversationParticipants = (
  conversationId: string,
  userIds: string[]
): Promise<Conversation> =>
  apiService.post<Conversation>(`${API_PATHS.CONVERSATIONS}/${conversationId}/participants`, { userIds });

export const removeConversationParticipant = (
  conversationId: string,
  userId: string
): Promise<void> =>
  apiService.delete<void>(`${API_PATHS.CONVERSATIONS}/${conversationId}/participants/${userId}`);

export const getMessagesPage = (
  conversationId: string,
  page = 1,
  pageSize = 50
): Promise<MessagesPage> => {
  const query = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
  return apiService.get<MessagesPage>(
    `${API_PATHS.CONVERSATIONS}/${conversationId}/messages?${query.toString()}`
  );
};

export const addMessageReaction = (
  conversationId: string,
  messageId: string,
  emoji: string
): Promise<Message> =>
  apiService
    .post<Message | { data: Message }>(
      `${API_PATHS.CONVERSATIONS}/${conversationId}/messages/${messageId}/reactions`,
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
