/** Shown on hover (desktop); touch users use the ⋮ menu copy of these. */
export const QUICK_REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'] as const;

export const TRANSLATE_TARGET_LANGS: Array<{ code: string; label: string }> = [
  { code: 'en', label: 'English' },
  { code: 'es', label: 'Spanish' },
  { code: 'fr', label: 'French' },
  { code: 'de', label: 'German' },
  { code: 'hi', label: 'Hindi' },
  { code: 'ar', label: 'Arabic' },
  { code: 'zh', label: 'Chinese' },
  { code: 'ja', label: 'Japanese' },
  { code: 'pt', label: 'Portuguese' },
  { code: 'it', label: 'Italian' },
  { code: 'nl', label: 'Dutch' },
  { code: 'ko', label: 'Korean' }
];

export const translateLangLabel = (code: string): string =>
  TRANSLATE_TARGET_LANGS.find((lang) => lang.code === code)?.label ?? code.toUpperCase();

/** Client → server: notify presence before unload / logout (handle on gateway alongside disconnect). */
export const CLIENT_GOING_OFFLINE_EVENT = 'going_offline';

export const SOCKET_ACK_TIMEOUT_MS = 8000;

/** `send_message` should fall back to REST quickly if the ack is slow or missing. */
export const SOCKET_SEND_MESSAGE_ACK_TIMEOUT_MS = 2800;
