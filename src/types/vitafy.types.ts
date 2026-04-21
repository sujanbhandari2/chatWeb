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

/** Serialized attachment from `messages.attachments` JSONB (`GET`/`POST` messages). */
export type VitafyMessageAttachmentApi = {
  fileUrl: string;
  size?: number;
  fileType?: string;
  fileName?: string | null;
  mimeType?: string | null;
  kind?: string | null;
};

/** Request item for `POST .../conversations/:id/messages` (`url` → stored as `fileUrl`). */
export type VitafyPostMessageAttachmentInput = {
  url: string;
  mimeType?: string;
  fileName?: string;
  byteSize?: number;
  kind?: string;
};

export type VitafyPostMessageBody = {
  senderId: string;
  type: string;
  /** Required when `attachments` is omitted or empty (non-empty after trim). */
  content?: string;
  attachments?: VitafyPostMessageAttachmentInput[];
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
  attachments?: VitafyMessageAttachmentApi[];
  translatedMessage?: string | null;
  transcribedMessage?: string | null;
  sender?: { id: string; name: string | null };
};

export type VitafyMessagesPageApi = {
  items: VitafyMessageApi[];
  page: number;
  pageSize: number;
  total: number;
};
