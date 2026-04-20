/**
 * Canonical Socket.IO event names (aligned with Vitafy chat backend).
 * Receipt commands reuse the same wire strings as the matching broadcasts.
 */

const MESSAGE_DELIVERED = 'message_delivered' as const;
const MESSAGE_READ = 'message_read' as const;

export const chatRealtimeEvents = {
  message: 'message',
  userTyping: 'user_typing',
  userStoppedTyping: 'user_stopped_typing',
  reactionAdded: 'reaction_added',
  messageDelivered: MESSAGE_DELIVERED,
  messageRead: MESSAGE_READ,
  userOnline: 'user_online',
  userOffline: 'user_offline'
} as const;

export type ChatRealtimeEventName = (typeof chatRealtimeEvents)[keyof typeof chatRealtimeEvents];

export const chatSocketClientEvents = {
  joinConversation: 'join_conversation',
  leaveConversation: 'leave_conversation',
  sendMessage: 'send_message',
  typingStart: 'typing_start',
  typingStop: 'typing_stop',
  reactMessage: 'react_message',
  removeReaction: 'remove_reaction',
  messageDelivered: chatRealtimeEvents.messageDelivered,
  messageRead: chatRealtimeEvents.messageRead
} as const;

export type ChatSocketClientEventName = (typeof chatSocketClientEvents)[keyof typeof chatSocketClientEvents];

/** Optional broadcast not listed in the current contract; safe to drop when server stops emitting. */
export const chatRealtimeLegacyEvents = {
  messageDeleted: 'message_deleted'
} as const;

/** Client → server events not in the published contract (may still exist on older gateways). */
export const chatSocketLegacyClientEvents = {
  deleteMessage: 'delete_message'
} as const;
