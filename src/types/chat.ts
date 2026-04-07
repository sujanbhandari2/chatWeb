/** Prisma conversation type enum — extend as backend adds values */
export type ConversationType = string;

export type MessageType = 'TEXT' | 'IMAGE' | 'VOICE';

/** User returned from POST /api/auth/create */
export interface AuthUser {
  id: string;
  name: string | null;
  email: string;
  tenantId: string;
  status: string | null;
}

export interface CreateAccountResponse {
  token: string;
  user: AuthUser;
}

/** @deprecated Use CreateAccountResponse; kept for gradual migration */
export type LoginResponse = CreateAccountResponse;

export interface PublicUser {
  id: string;
  name: string | null;
  email: string;
  avatarUrl: string | null;
  status: string | null;
}

export interface TenantUser {
  id: string;
  tenantId: string;
  name: string | null;
  email: string;
  avatarUrl: string | null;
  status: string | null;
  createdAt: string;
  isOnline: boolean;
}

export interface ConversationParticipant {
  userId: string;
  conversationId: string;
  user: PublicUser;
}

export interface Conversation {
  id: string;
  tenantId: string;
  type: ConversationType;
  title: string | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  participants: ConversationParticipant[];
}

export interface MessageReaction {
  id: string;
  messageId: string;
  userId: string;
  emoji: string;
  createdAt: string;
  user: PublicUser;
}

export interface ReplyToMessage {
  id: string;
  senderId: string;
  content: string;
  messageType: MessageType;
}

export interface ReadReceipt {
  id: string;
  messageId: string;
  userId: string;
  readAt: string;
}

export interface DeliveredReceipt {
  id: string;
  messageId: string;
  userId: string;
  deliveredAt: string;
}

export interface Message {
  id: string;
  conversationId: string;
  senderId: string;
  content: string;
  messageType: MessageType;
  replyToMessageId: string | null;
  createdAt: string;
  attachments: unknown[];
  replyToMessage?: ReplyToMessage | null;
  reactions: MessageReaction[];
  /** Legacy / socket — not always present on REST payloads */
  tenantId?: string;
  type?: MessageType;
  deletedAt?: string | null;
  deliveredReceipts?: DeliveredReceipt[];
  readReceipts?: ReadReceipt[];
}

export interface MessagesPage {
  data: Message[];
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

export interface UploadFileResponse {
  url: string;
  key: string;
  mimeType: string;
  mimetype: string;
  size: number;
}

export interface TranscribeResponse {
  data: {
    text: string;
    fromCache: boolean;
  };
}

export interface TranslateResponse {
  data: {
    translatedText: string;
  };
}

export interface HealthResponse {
  status: string;
}
