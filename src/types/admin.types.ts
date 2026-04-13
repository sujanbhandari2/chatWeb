export interface AdminClient {
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

export function parseAdminClient(raw: unknown): AdminClient | null {
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

/** POST /admin/clients may return the entity or `{ data }`. */
export function extractAdminClientFromCreateResponse(
  res: unknown,
  fallback: Pick<AdminClient, 'name' | 'email'>
): AdminClient | null {
  const direct = parseAdminClient(res);
  if (direct) {
    return direct;
  }
  if (res && typeof res === 'object' && 'data' in res) {
    const inner = parseAdminClient((res as { data: unknown }).data);
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
  return {
    id,
    name: o.name != null ? String(o.name) : null,
    expiresAt: o.expiresAt != null ? String(o.expiresAt) : o.expires_at != null ? String(o.expires_at) : null,
    revokedAt: o.revokedAt != null ? String(o.revokedAt) : o.revoked_at != null ? String(o.revoked_at) : null,
    scopes: Array.isArray(scopes) ? scopes.filter((s): s is string => typeof s === 'string') : undefined
  };
}

export function pickApiKeyPlaintext(payload: unknown): string | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const o = payload as Record<string, unknown>;
  const k = o.key ?? o.secret ?? o.token ?? o.apiKey;
  return typeof k === 'string' && k.trim() !== '' ? k.trim() : undefined;
}

export function unwrapAdminList<T>(raw: unknown, parse: (item: unknown) => T | null): T[] {
  const list: unknown[] = Array.isArray(raw)
    ? raw
    : raw && typeof raw === 'object' && 'data' in raw && Array.isArray((raw as { data: unknown }).data)
      ? (raw as { data: unknown[] }).data
      : [];
  return list.map(parse).filter((x): x is T => x !== null);
}
