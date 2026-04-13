/**
 * Optional widget / dev credentials applied to every axios request (not React state).
 * Bearer JWT still comes from `useAuthStore` when present.
 */
let runtimeApiKey: string | undefined;
let runtimeTenantId: string | undefined;

export function setRuntimeApiCredentials(overrides: { apiKey?: string; tenantId?: string }): void {
  runtimeApiKey = overrides.apiKey?.trim() || undefined;
  runtimeTenantId = overrides.tenantId?.trim() || undefined;
}

export function getResolvedApiKey(): string | undefined {
  if (runtimeApiKey) {
    return runtimeApiKey;
  }
  const fromEnv =
    typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_KEY
      ? String(import.meta.env.VITE_API_KEY).trim()
      : '';
  return fromEnv || undefined;
}

export function getResolvedTenantId(): string | undefined {
  return runtimeTenantId;
}
