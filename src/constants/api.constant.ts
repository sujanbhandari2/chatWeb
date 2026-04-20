/**
 * Paths relative to axios `baseURL` (typically `…/api` from `getApiBaseUrl()`).
 * OpenAPI servers use `/api/v1/...`; with base `…/api` these are `/v1/...`.
 * When the backend OpenAPI changes, refresh `src/types/openapi/*-openapi.ts` via `npm run codegen:api`.
 */
export const API_PATHS = {
  /** Tenant app (JWT + optional API key / company scope on some routes). */
  TENANT: {
    LOGIN: '/v1/auth/tenant/login',
    HEALTH: '/v1/system/health',
    SHARED_ME: '/v1/shared/me',
    SHARED_API_KEYS: '/v1/shared/api-keys'
  },
  /** Chat REST (`X-Api-Key: access:secret`) — OpenAPI `/api/v1/chat/...` with base `…/api`. */
  CHAT: {
    TENANT: '/v1/chat/tenant',
    USERS: '/v1/chat/users',
    CONVERSATIONS: '/v1/chat/conversations'
  },
  /** Admin JWT console (separate from embed widget). */
  ADMIN: {
    LOGIN: '/v1/admin/login',
    ME: '/v1/admin/me',
    /** Admin OpenAPI: tenant accounts under `/api/v1/admin/tenants`. */
    TENANTS: '/v1/admin/tenants'
  },
  UPLOAD: '/upload',
  SPEECH: {
    TRANSCRIBE: '/speech/transcribe',
    TRANSLATE: '/speech/translate'
  }
} as const;
