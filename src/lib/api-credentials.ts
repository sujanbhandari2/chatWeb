import { resolveXApiKeyHeaderValue } from '../utils/chat-api-key.utils';

/**
 * Optional widget / dev API key applied to requests (not React state).
 * Bearer JWT still comes from `useAuthStore` when present.
 */
let runtimeApiKey: string | undefined;

export function setRuntimeApiCredentials(overrides: { apiKey?: string }): void {
  runtimeApiKey = overrides.apiKey?.trim() || undefined;
}

export function getResolvedApiKey(): string | undefined {
  if (runtimeApiKey) {
    return runtimeApiKey;
  }
  const id =
    typeof import.meta !== 'undefined' && import.meta.env?.VITE_WIDGET_ACCESS_KEY
      ? String(import.meta.env.VITE_WIDGET_ACCESS_KEY).trim()
      : '';
  const secret =
    typeof import.meta !== 'undefined' && import.meta.env?.VITE_WIDGET_SECRET_KEY
      ? String(import.meta.env.VITE_WIDGET_SECRET_KEY).trim()
      : '';
  return resolveXApiKeyHeaderValue({ accessKey: id, secretKey: secret }) || undefined;
}
