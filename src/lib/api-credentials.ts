import { resolveXApiKeyHeaderValue } from '../utils/chat-api-key.utils';
import { useAuthStore } from '../store/useAuthStore';

/**
 * Optional widget / dev credentials applied to every axios request (not React state).
 * Bearer JWT still comes from `useAuthStore` when present.
 */
let runtimeApiKey: string | undefined;
let runtimeCompanyId: string | undefined;

export function setRuntimeApiCredentials(overrides: { apiKey?: string; companyId?: string }): void {
  runtimeApiKey = overrides.apiKey?.trim() || undefined;
  runtimeCompanyId = overrides.companyId?.trim() || undefined;
}

function widgetCompanyIdFromEnv(): string | undefined {
  const fromEnv =
    typeof import.meta !== 'undefined' && import.meta.env?.VITE_WIDGET_COMPANY_ID
      ? String(import.meta.env.VITE_WIDGET_COMPANY_ID).trim()
      : '';
  if (fromEnv) {
    return fromEnv;
  }
  const legacy =
    typeof import.meta !== 'undefined' && import.meta.env?.VITE_WIDGET_TENANT_ID
      ? String(import.meta.env.VITE_WIDGET_TENANT_ID).trim()
      : '';
  return legacy || undefined;
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

/** Company id from embed runtime / merged widget config, then `VITE_WIDGET_*` env (same order as API key env fallback). */
export function getResolvedCompanyId(): string | undefined {
  if (runtimeCompanyId?.trim()) {
    return runtimeCompanyId.trim();
  }
  return widgetCompanyIdFromEnv();
}

/**
 * Value for `X-Company-Id`: explicit per-request header first, then embed/env, then the logged-in chat user.
 */
export function resolveEffectiveXCompanyId(perRequestHeader: string | undefined): string | undefined {
  const explicit = perRequestHeader?.trim();
  if (explicit) {
    return explicit;
  }
  return (
    getResolvedCompanyId()?.trim() || useAuthStore.getState().user?.companyId?.trim() || undefined
  );
}
