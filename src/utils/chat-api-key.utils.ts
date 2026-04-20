/**
 * Chat gateway expects `X-Api-Key` to be the merged credential (typically **`publicId:secret`**) from env
 * (`VITE_WIDGET_ACCESS_KEY` / secret merge) or embed `backend.accessKey` / `apiKey` / `secretKey`.
 * Legacy values that still start with **`accessKey:`** are stripped so pasted admin strings work.
 */

export type ChatApiKeyParts = {
  accessKey?: string | null;
  apiKey?: string | null;
  secretKey?: string | null;
};

/** Builds the value sent as the `X-Api-Key` header. */
export function resolveXApiKeyHeaderValue(parts: ChatApiKeyParts): string | undefined {
  const id = (parts.accessKey?.trim() || parts.apiKey?.trim()) || '';
  const secret = parts.secretKey?.trim() || '';
  if (id && secret) {
    return `${id}:${secret}`;
  }
  if (id) {
    return id;
  }
  return secret || undefined;
}

const LEGACY_ACCESS_KEY_HEADER_PREFIX = 'accessKey:';

/** Trims the credential and removes any legacy `accessKey:` prefix (repeatable). */
export function formatWireXApiKeyValue(raw: string | undefined): string | undefined {
  let t = raw?.trim();
  if (!t) {
    return undefined;
  }
  const prefixLower = LEGACY_ACCESS_KEY_HEADER_PREFIX.toLowerCase();
  for (;;) {
    const lower = t.toLowerCase();
    if (!lower.startsWith(prefixLower)) {
      break;
    }
    t = t.slice(LEGACY_ACCESS_KEY_HEADER_PREFIX.length).trim();
    if (!t) {
      return undefined;
    }
  }
  return t;
}

function unwrapAdminEntity(payload: unknown): Record<string, unknown> | null {
  if (!payload || typeof payload !== 'object') {
    return null;
  }
  const p = payload as Record<string, unknown>;
  const data = p.data;
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    return data as Record<string, unknown>;
  }
  return p;
}

function pickFirstString(o: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === 'string' && v.trim() !== '') {
      return v.trim();
    }
  }
  return undefined;
}

/**
 * Parses POST create-tenant-api-key JSON into the raw `X-Api-Key` credential (typically `id:secret`).
 */
export function parseAdminCreateApiKeyHeaderValue(payload: unknown): string | undefined {
  const o = unwrapAdminEntity(payload);
  if (!o) {
    return undefined;
  }
  const accessKey = pickFirstString(o, ['accessKey', 'access_key']);
  const secretKey = pickFirstString(o, ['secretKey', 'secret_key', 'secret', 'clientSecret', 'client_secret']);
  const keyOrToken = pickFirstString(o, ['key', 'token', 'apiKey']);

  if (keyOrToken?.includes(':') && !accessKey) {
    return keyOrToken;
  }

  const secret =
    secretKey ??
    (accessKey && keyOrToken && !keyOrToken.includes(':') ? keyOrToken : undefined);

  return (
    resolveXApiKeyHeaderValue({ accessKey, secretKey: secret }) ??
    keyOrToken ??
    accessKey
  );
}
