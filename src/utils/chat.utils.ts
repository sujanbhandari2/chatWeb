import type {
  Conversation,
  Message,
  MessageReaction,
  MessageType,
  PublicUser,
  TenantUser
} from '../types/chat';

export type UserLabel = { name: string | null; email: string };

export const userDisplayName = (user: UserLabel): string => {
  const raw = (user.name?.trim() || user.email.split('@')[0] || user.email).replace(/[_-]/g, ' ');
  return raw
    .split(/\s+/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
};

export const userInitials = (user: UserLabel): string => {
  const label = userDisplayName(user);
  const chunks = label.split(' ').filter(Boolean);
  const a = (chunks[0]?.[0] ?? user.email[0] ?? 'U').toUpperCase();
  const b = (chunks[1]?.[0] ?? chunks[0]?.[1] ?? '').toUpperCase();
  return a + b;
};

export function getMessageType(message: Message): MessageType {
  return message.messageType ?? message.type ?? 'TEXT';
}

export function normalizeMessage(message: Message): Message {
  const legacy = message as Message & { tenantId?: string };
  const companyId = message.companyId ?? legacy.tenantId;
  const raw = message.reactions ?? [];
  const reactions: MessageReaction[] = raw.map((r) => {
    const legacyEmoji = (r as MessageReaction & { reactionType?: string }).reactionType;
    return {
      ...r,
      emoji: r.emoji ?? legacyEmoji ?? '👍',
      user:
        r.user ??
        ({
          id: r.userId,
          name: null,
          email: '…',
          avatarUrl: null,
          status: null
        } satisfies PublicUser)
    };
  });
  return {
    ...message,
    ...(companyId !== undefined ? { companyId } : {}),
    reactions,
    attachments: message.attachments ?? []
  };
}

export function summarizeReactions(
  reactions: MessageReaction[],
  currentUserId: string
): Array<{ emoji: string; count: number; title: string; mine: boolean }> {
  const byEmoji = new Map<string, MessageReaction[]>();
  for (const r of reactions) {
    const emoji = r.emoji || '👍';
    const list = byEmoji.get(emoji) ?? [];
    list.push(r);
    byEmoji.set(emoji, list);
  }
  return [...byEmoji.entries()].map(([emoji, list]) => {
    const mine = list.some((item) => item.userId === currentUserId);
    const title = list.map((item) => userDisplayName(item.user)).join(', ');
    return { emoji, count: list.length, title, mine };
  });
}

export const isGlobalConversation = (conversation: Conversation): boolean => conversation.type === 'GLOBAL';

export const isGroupConversation = (conversation: Conversation): boolean => conversation.type === 'GROUP';

/**
 * Last-activity time for ordering chat rows (sidebar). Supports camelCase + snake_case from APIs.
 * Used for oldest → newest so the latest conversation sits at the bottom.
 */
export function getConversationActivityTimeMs(conversation: Conversation): number {
  const r = conversation as unknown as Record<string, unknown>;
  const iso =
    (typeof r.updatedAt === 'string' && r.updatedAt.trim() !== '' ? r.updatedAt : undefined) ??
    (typeof r.updated_at === 'string' && r.updated_at.trim() !== '' ? r.updated_at : undefined) ??
    (typeof r.lastMessageAt === 'string' && r.lastMessageAt.trim() !== '' ? r.lastMessageAt : undefined) ??
    (typeof r.last_message_at === 'string' && r.last_message_at.trim() !== '' ? r.last_message_at : undefined) ??
    (typeof r.createdAt === 'string' && r.createdAt.trim() !== '' ? r.createdAt : undefined) ??
    (typeof r.created_at === 'string' && r.created_at.trim() !== '' ? r.created_at : undefined) ??
    '';
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : 0;
}

export function pickUserId(payload: unknown): string | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const record = payload as Record<string, unknown>;
  const id = record.userId ?? record.user_id ?? record.id;
  return typeof id === 'string' ? id : undefined;
}

export function pickPresence(payload: unknown): { userId: string; isOnline: boolean } | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const record = payload as Record<string, unknown>;
  const userId = pickUserId(record);
  if (!userId) {
    return undefined;
  }
  if (typeof record.isOnline === 'boolean') {
    return { userId, isOnline: record.isOnline };
  }
  if (typeof record.online === 'boolean') {
    return { userId, isOnline: record.online };
  }
  return undefined;
}

export const tenantUserAsLabel = (u: TenantUser): UserLabel => ({
  name: u.name,
  email: u.email
});
