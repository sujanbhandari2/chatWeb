/** Shown on hover (desktop); touch users use the ⋮ menu copy of these. */
export const QUICK_REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'] as const;

/** Client → server: notify presence before unload / logout (handle on gateway alongside disconnect). */
export const CLIENT_GOING_OFFLINE_EVENT = 'going_offline';

export const SOCKET_ACK_TIMEOUT_MS = 8000;
