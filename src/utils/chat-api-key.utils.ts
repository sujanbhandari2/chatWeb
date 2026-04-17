/**
 * Chat gateway expects `X-Api-Key` in the form **`accessKey:<credential>`** where `<credential>` is
 * the value from env (`VITE_WIDGET_ACCESS_KEY` / secret merge) or the merged embed id:secret.
 * Embedders set `backend.accessKey` / `apiKey` / `secretKey` without the `accessKey:` prefix; axios adds it.
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

const WIRE_API_KEY_PREFIX = 'accessKey:';

/** Normalizes the resolved credential to the wire form `accessKey:…` (idempotent). */
export function formatWireXApiKeyValue(raw: string | undefined): string | undefined {
  const t = raw?.trim();
  if (!t) {
    return undefined;
  }
  const lower = t.toLowerCase();
  if (lower.startsWith(WIRE_API_KEY_PREFIX.toLowerCase())) {
    return t;
  }
  return `${WIRE_API_KEY_PREFIX}${t}`;
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
 * Parses POST create-client-api-key JSON into the header string for chat (`accessKey:secretKey`).
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
