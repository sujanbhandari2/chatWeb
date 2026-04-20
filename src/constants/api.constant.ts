/** Relative to API base (`getApiBaseUrl()` — includes `/api`). Vitafy: `/api/v1/...` (`api_doc.md`). */
export const API_PATHS = {
  ADMIN: {
    LOGIN: '/v1/admin/login',
    ME: '/v1/admin/me',
    TENANTS: '/v1/admin/tenants',
    tenant: (id: string) => `/v1/admin/tenants/${id}`,
    tenantApiKeys: (tenantId: string) => `/v1/admin/tenants/${tenantId}/api-keys`,
    tenantApiKeyRevoke: (tenantId: string, keyId: string) =>
      `/v1/admin/tenants/${tenantId}/api-keys/${keyId}/revoke`
  },
  AUTH: {
    TENANT_LOGIN: '/v1/auth/tenant/login'
  },
  SYSTEM: {
    HEALTH: '/v1/system/health'
  },
  CHAT: {
    TENANT: '/v1/chat/tenant',
    USERS: '/v1/chat/users',
    CONVERSATIONS: '/v1/chat/conversations',
    conversationParticipants: (conversationId: string) =>
      `/v1/chat/conversations/${conversationId}/participants`,
    conversationMessages: (conversationId: string) =>
      `/v1/chat/conversations/${conversationId}/messages`
  },
  /** Legacy non-Vitafy uploads / speech (unchanged paths). */
  UPLOAD: '/upload',
  SPEECH: {
    TRANSCRIBE: '/speech/transcribe',
    TRANSLATE: '/speech/translate'
  }
} as const;
