/** Relative to API base (includes `/api` prefix in baseURL). */
export const API_PATHS = {
  AUTH: {
    CREATE: '/auth/create',
    LOGIN: '/auth/login'
  },
  CONVERSATIONS: '/conversations',
  USERS: '/users',
  UPLOAD: '/upload',
  SPEECH: {
    TRANSCRIBE: '/speech/transcribe',
    TRANSLATE: '/speech/translate'
  },
  HEALTH: '/health'
} as const;
