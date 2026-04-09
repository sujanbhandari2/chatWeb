export type Role = 'CLIENT' | 'AGENT' | 'ADMIN';

export type UserStatus = 'ACTIVE' | 'INACTIVE' | 'SUSPENDED';

export type MessageType = 'TEXT' | 'IMAGE' | 'VOICE';

export type DevicePlatform = 'IOS' | 'ANDROID' | 'WEB';

/** User from auth responses (POST /api/auth/create | login) */
export interface AuthUser {
  id: string;
  username: string;
  tenantId: string;
  role: Role;
  name: string;
  email: string;
  status: UserStatus;
}

export interface CreateAccountResponse {
  token: string;
  user: AuthUser;
}

/** @deprecated Use CreateAccountResponse */
export type LoginResponse = CreateAccountResponse;

/** Nested user on conversation participants (REST list shape) */
export interface ConversationParticipantUser {
  id: string;
  username: string;
  role: Role;
  name?: string | null;
  email?: string | null;
}

/** Display-oriented user (participants + reactions); tolerate partial API shapes */
export interface PublicUser {
  id: string;
  username?: string;
  name: string | null;
  email: string;
  avatarUrl?: string | null;
  status?: string | null;
  role?: Role;
}

export interface TenantUser {
  id: string;
  tenantId: string;
  username: string;
  name: string | null;
  email: string;
  role: Role;
  status: UserStatus;
  createdAt: string;
  isOnline: boolean;
}

export interface ConversationParticipant {
  id: string;
  conversationId: string;
  userId: string;
  user: ConversationParticipantUser;
}

/** GET /api/conversations item */
export interface Conversation {
  id: string;
  tenantId: string;
  isGlobal: boolean;
  createdAt: string;
  participants: ConversationParticipant[];
  /** Not in current API reference; kept optional for sorting / legacy payloads */
  updatedAt?: string;
  title?: string | null;
  type?: string;
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

export interface HealthResponse {
  status: string;
}

/** POST /api/speech/transcribe — 200 body */
export interface TranscribeResponse {
  text: string;
}

/** POST /api/speech/translate — 200 body */
export interface TranslateResponse {
  translatedText: string;
}
