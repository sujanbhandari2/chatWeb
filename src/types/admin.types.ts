export interface AdminTenant {
  id: string;
  name: string;
  email: string;
}

export interface AdminApiKeyRow {
  id: string;
  name?: string | null;
  scopes?: string[];
  expiresAt?: string | null;
  revokedAt?: string | null;
  /** Full key when the list endpoint returns it (uncommon). */
  accessKey?: string | null;
  /** Masked / prefix hint from the API (e.g. `sk_live_…abcd`). */
  keyPreview?: string | null;
}

/** Plaintext key material — only present on create. */
export interface AdminApiKeyCreated extends AdminApiKeyRow {
  key?: string;
  secret?: string;
  token?: string;
}

export function pickBearerToken(payload: unknown, depth = 0): string | undefined {
  if (depth > 5 || !payload || typeof payload !== 'object') {
    return undefined;
  }
  const p = payload as Record<string, unknown>;
  const t = p.access_token ?? p.accessToken ?? p.token;
  if (typeof t === 'string' && t.trim() !== '') {
    return t.trim();
  }
  const nested = p.data;
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
    return pickBearerToken(nested, depth + 1);
  }
  return undefined;
}

export function parseAdminTenant(raw: unknown): AdminTenant | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }
  const o = raw as Record<string, unknown>;
  const id = o.id != null ? String(o.id) : '';
  if (!id) {
    return null;
  }
  return {
    id,
    name: o.name != null ? String(o.name) : '',
    email: o.email != null ? String(o.email) : ''
  };
}

/** POST /admin/tenants may return the entity or `{ data }`. */
export function extractAdminTenantFromCreateResponse(
  res: unknown,
  fallback: Pick<AdminTenant, 'name' | 'email'>
): AdminTenant | null {
  const direct = parseAdminTenant(res);
  if (direct) {
    return direct;
  }
  if (res && typeof res === 'object' && 'data' in res) {
    const inner = parseAdminTenant((res as { data: unknown }).data);
    if (inner) {
      return inner;
    }
  }
  if (res && typeof res === 'object' && 'id' in res) {
    const id = String((res as { id: unknown }).id);
    if (id) {
      return { id, name: fallback.name, email: fallback.email };
    }
  }
  return null;
}

export function parseAdminApiKeyRow(raw: unknown): AdminApiKeyRow | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }
  const o = raw as Record<string, unknown>;
  const id = o.id != null ? String(o.id) : '';
  if (!id) {
    return null;
  }
  const scopes = o.scopes;
  const accessRaw = o.accessKey ?? o.access_key ?? o.key ?? o.secret ?? o.token ?? o.apiKey;
  const accessKey =
    typeof accessRaw === 'string' && accessRaw.trim() !== '' ? accessRaw.trim() : null;
  const previewRaw =
    o.keyPreview ?? o.key_preview ?? o.keyPrefix ?? o.prefix ?? o.maskedKey ?? o.masked_key;
  const keyPreview =
    typeof previewRaw === 'string' && previewRaw.trim() !== '' ? previewRaw.trim() : null;
  return {
    id,
    name: o.name != null ? String(o.name) : null,
    expiresAt: o.expiresAt != null ? String(o.expiresAt) : o.expires_at != null ? String(o.expires_at) : null,
    revokedAt: o.revokedAt != null ? String(o.revokedAt) : o.revoked_at != null ? String(o.revoked_at) : null,
    scopes: Array.isArray(scopes) ? scopes.filter((s): s is string => typeof s === 'string') : undefined,
    accessKey,
    keyPreview
  };
}

/** Row + id from POST create key response (root or `{ data }`). */
export function parseAdminApiKeyFromCreateResponse(res: unknown): AdminApiKeyRow | null {
  const direct = parseAdminApiKeyRow(res);
  if (direct) {
    return direct;
  }
  if (res && typeof res === 'object' && 'data' in res) {
    return parseAdminApiKeyRow((res as { data: unknown }).data);
  }
  return null;
}

export function unwrapAdminList<T>(raw: unknown, parse: (item: unknown) => T | null): T[] {
  const list: unknown[] = Array.isArray(raw)
    ? raw
    : raw && typeof raw === 'object' && 'data' in raw && Array.isArray((raw as { data: unknown }).data)
      ? (raw as { data: unknown[] }).data
      : [];
  return list.map(parse).filter((x): x is T => x !== null);
}
