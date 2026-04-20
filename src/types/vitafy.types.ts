/** Shapes returned by Vitafy Chat backend (`api_doc.md`). */

export type VitafyTenantLoginResponse = {
  token: string;
  id: string;
  email: string;
  name: string;
  settings: Record<string, unknown>;
};

export type VitafyChatUserRow = {
  id: string;
  tenantId: string;
  providerId: string;
  providerUserId: string;
  email: string;
  name: string | null;
  status: string;
  createdAt?: string;
  updatedAt?: string;
  /** Present on `GET /v1/chat/users` — live directory presence */
  isOnline?: boolean;
  is_online?: boolean;
};

export type VitafyConversationParticipantApi = {
  role?: string;
  userId?: string;
  chatUser?: {
    id: string;
    providerId?: string;
    providerUserId?: string;
    name: string | null;
    email: string;
    status: string;
  };
};

export type VitafyConversationApi = {
  id: string;
  tenantId?: string;
  type: string;
  title?: string | null;
  createdBy?: string | null;
  createdAt: string;
  updatedAt?: string;
  participants: VitafyConversationParticipantApi[];
};

export type VitafyMessageApi = {
  id: string;
  conversationId: string;
  tenantId?: string;
  senderId: string;
  type: string;
  content: string;
  createdAt: string;
  deletedAt?: string | null;
  sender?: { id: string; name: string | null };
};

export type VitafyMessagesPageApi = {
  items: VitafyMessageApi[];
  page: number;
  pageSize: number;
  total: number;
};
