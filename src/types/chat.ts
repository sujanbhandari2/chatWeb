export type Role = 'CLIENT' | 'AGENT' | 'ADMIN';
export type MessageType = 'TEXT' | 'IMAGE' | 'VOICE';

export interface AuthUser {
  id: string;
  tenantId: string;
  role: Role;
  username: string;
}

export interface LoginResponse {
  token: string;
  user: AuthUser;
}

export interface TenantUser {
  id: string;
  tenantId: string;
  username: string;
  role: Role;
  isOnline: boolean;
  createdAt: string;
}

export interface ConversationParticipant {
  id: string;
  userId: string;
  user: {
    id: string;
    username: string;
    role: Role;
  };
}

export interface Conversation {
  id: string;
  tenantId: string;
  isGlobal: boolean;
  createdAt: string;
  participants: ConversationParticipant[];
}

export interface MessageReaction {
  id: string;
  messageId: string;
  userId: string;
  reactionType: string;
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
  tenantId: string;
  senderId: string;
  type: MessageType;
  content: string;
  deletedAt: string | null;
  createdAt: string;
  reactions: MessageReaction[];
  deliveredReceipts: DeliveredReceipt[];
  readReceipts: ReadReceipt[];
}
