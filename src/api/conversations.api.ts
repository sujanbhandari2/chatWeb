import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { Conversation, MessagesPage } from '../types/chat';
import type { VitafyConversationApi, VitafyMessagesPageApi } from '../types/vitafy.types';
import { mapConversationFromApi, mapMessagesPageFromApi } from '../utils/vitafy-chat.utils';

export const listConversations = (forUserId: string): Promise<Conversation[]> =>
  apiService
    .get<VitafyConversationApi[]>(
      `${API_PATHS.CHAT.CONVERSATIONS}?forUserId=${encodeURIComponent(forUserId)}`
    )
    .then((rows) => rows.map(mapConversationFromApi));

export const createConversation = (participantIds: string[]): Promise<Conversation> =>
  apiService
    .post<VitafyConversationApi>(API_PATHS.CHAT.CONVERSATIONS, {
      type: 'DIRECT',
      participantIds
    })
    .then(mapConversationFromApi);

export const createDirectConversation = (
  currentChatUserId: string,
  otherChatUserId: string
): Promise<Conversation> =>
  apiService
    .post<VitafyConversationApi>(API_PATHS.CHAT.CONVERSATIONS, {
      type: 'DIRECT',
      participantIds: [currentChatUserId, otherChatUserId].filter(
        (id, i, arr) => arr.indexOf(id) === i
      )
    })
    .then(mapConversationFromApi);

/** Title is accepted for UI compatibility but is not persisted by the Vitafy chat API. */
export const createGroupConversation = (
  _title: string,
  creatorUserId: string,
  participantIdsIncludingSelf: string[]
): Promise<Conversation> => {
  const extra = participantIdsIncludingSelf.filter((id) => id !== creatorUserId);
  return apiService
    .post<VitafyConversationApi>(API_PATHS.CHAT.CONVERSATIONS, {
      type: 'GROUP',
      creatorUserId,
      participantIds: extra
    })
    .then(mapConversationFromApi);
};

export const deleteConversationById = (_conversationId: string): Promise<void> =>
  Promise.reject(new Error('Deleting conversations is not supported by this API.'));

export const updateConversationById = (
  _conversationId: string,
  _body: { title: string }
): Promise<Conversation> =>
  Promise.reject(new Error('Renaming conversations is not supported by this API.'));

export const addConversationParticipants = async (
  conversationId: string,
  userIds: string[],
  options: { actorUserId?: string; conversationType: string }
): Promise<void> => {
  const isGroup = options.conversationType === 'GROUP';
  for (const userId of userIds) {
    const body: { userId: string; actorUserId?: string } = { userId };
    if (isGroup && options.actorUserId) {
      body.actorUserId = options.actorUserId;
    }
    await apiService.post(API_PATHS.CHAT.conversationParticipants(conversationId), body);
  }
};

export const removeConversationParticipant = (
  _conversationId: string,
  _userId: string
): Promise<void> =>
  Promise.reject(new Error('Removing participants is not supported by this API.'));

export const getMessagesPage = (
  conversationId: string,
  page = 1,
  pageSize = 50
): Promise<MessagesPage> => {
  const query = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
  return apiService
    .get<VitafyMessagesPageApi>(
      `${API_PATHS.CHAT.conversationMessages(conversationId)}?${query.toString()}`
    )
    .then(mapMessagesPageFromApi);
};
