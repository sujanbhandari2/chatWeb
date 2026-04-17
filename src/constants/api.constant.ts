/**
 * Paths relative to axios `baseURL` (typically `…/api` from `getApiBaseUrl()`).
 * OpenAPI servers use `/api/v1/...`; with base `…/api` these are `/v1/...`.
 */
export const API_PATHS = {
  /** Client app (JWT + optional API key / company scope on some routes). */
  CLIENT: {
    LOGIN: '/v1/auth/client/login',
    HEALTH: '/v1/system/health',
    SHARED_ME: '/v1/shared/me',
    SHARED_API_KEYS: '/v1/shared/api-keys'
  },
  /** Chat (OpenAPI “Chat API”: `X-Api-Key` / HMAC + `X-Company-Id` where required). */
  CHAT: {
    CLIENTS: '/v1/chat/clients',
    USERS: '/v1/chat/users',
    CONVERSATIONS: '/v1/chat/conversations'
  },
  /** Admin JWT console (separate from embed widget). */
  ADMIN: {
    LOGIN: '/v1/admin/login',
    ME: '/v1/admin/me',
    CLIENTS: '/v1/admin/clients'
  },
  UPLOAD: '/upload',
  SPEECH: {
    TRANSCRIBE: '/speech/transcribe',
    TRANSLATE: '/speech/translate'
  }
} as const;
