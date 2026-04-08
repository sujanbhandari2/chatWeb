import { isGlobalConversation, userDisplayName } from '../../utils/chat.utils';
import type { AuthUser, Conversation } from '../../types/chat';

export function conversationTitleForUser(conversation: Conversation, user: AuthUser): string {
  if (isGlobalConversation(conversation)) {
    return 'System Broadcast (All Users)';
  }
  if (conversation.title?.trim()) {
    return conversation.title.trim();
  }
  const others = conversation.participants.filter((item) => item.userId !== user.id);
  if (others.length === 0) {
    return 'Just You';
  }
  if (others.length === 1) {
    return userDisplayName(others[0].user);
  }
  return `${userDisplayName(others[0].user)} + ${others.length - 1}`;
}

export function findDirectConversation(
  conversations: Conversation[],
  userId: string,
  targetUserId: string
): Conversation | undefined {
  return conversations.find((conversation) => {
    if (isGlobalConversation(conversation)) {
      return false;
    }
    const participantIds = conversation.participants.map((item) => item.userId);
    return (
      participantIds.length === 2 &&
      participantIds.includes(userId) &&
      participantIds.includes(targetUserId)
    );
  });
}
