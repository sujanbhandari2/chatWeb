import type {
  AuthUser,
  Conversation,
  ConversationParticipant,
  Message,
  MessageType,
  MessagesPage,
  TenantUser
} from '../types/chat';
import type {
  VitafyChatUserRow,
  VitafyConversationApi,
  VitafyMessageApi,
  VitafyMessagesPageApi
} from '../types/vitafy.types';

function pickChatUserOnlineFlag(row: VitafyChatUserRow): boolean {
  if (typeof row.isOnline === 'boolean') {
    return row.isOnline;
  }
  if (typeof row.is_online === 'boolean') {
    return row.is_online;
  }
  return false;
}

export function mapChatUserToTenantUser(row: VitafyChatUserRow): TenantUser {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    email: row.email,
    avatarUrl: null,
    status: row.status,
    createdAt: row.createdAt ?? new Date().toISOString(),
    isOnline: pickChatUserOnlineFlag(row)
  };
}

export function buildAuthUserFromVitafySession(
  tenant: { id: string; email: string; name: string },
  chatUser: VitafyChatUserRow
): AuthUser {
  return {
    id: chatUser.id,
    name: chatUser.name ?? chatUser.email,
    email: chatUser.email,
    tenantId: tenant.id,
    status: chatUser.status
  };
}

function mapParticipant(p: VitafyConversationApi['participants'][number]): ConversationParticipant {
  const cu = p.chatUser;
  const userId = p.userId ?? cu?.id ?? '';
  return {
    userId,
    conversationId: '',
    user: {
      id: cu?.id ?? userId,
      name: cu?.name ?? null,
      email: cu?.email ?? '',
      avatarUrl: null,
      status: cu?.status ?? null
    }
  };
}

export function mapConversationFromApi(raw: VitafyConversationApi): Conversation {
  const participants = raw.participants.map((item) => ({
    ...mapParticipant(item),
    conversationId: raw.id
  }));
  return {
    id: raw.id,
    tenantId: raw.tenantId ?? '',
    type: raw.type,
    title: raw.title ?? null,
    createdBy: raw.createdBy ?? null,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt ?? raw.createdAt,
    participants
  };
}

const MESSAGE_TYPES = new Set<MessageType>([
  'TEXT',
  'IMAGE',
  'VOICE',
  'VIDEO',
  'FILE',
  'LINK',
  'OTHER'
]);

export function mapApiMessageToMessage(m: VitafyMessageApi): Message {
  const mt: MessageType = MESSAGE_TYPES.has(m.type as MessageType) ? (m.type as MessageType) : 'TEXT';
  return {
    id: m.id,
    conversationId: m.conversationId,
    senderId: m.senderId,
    content: m.content,
    messageType: mt,
    type: mt,
    replyToMessageId: null,
    createdAt: m.createdAt,
    deletedAt: m.deletedAt ?? null,
    attachments: m.attachments?.length ? m.attachments : [],
    reactions: [],
    tenantId: m.tenantId,
    transcribedMessage: m.transcribedMessage,
    translatedMessage: m.translatedMessage
  };
}

export function mapMessagesPageFromApi(page: VitafyMessagesPageApi): MessagesPage {
  const data = [...page.items].map(mapApiMessageToMessage).sort(
    (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
  );
  const totalPages = page.pageSize > 0 ? Math.max(1, Math.ceil(page.total / page.pageSize)) : 1;
  return {
    data,
    pagination: {
      page: page.page,
      pageSize: page.pageSize,
      total: page.total,
      totalPages
    }
  };
}
