import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import type { LoginInput, RegisterInput } from '../schemas/auth.schemas';
import type { CreateAccountResponse } from '../types/chat';
import { createChatUser } from './chat.api';

function pickRecord(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function mapToAuthUser(raw: Record<string, unknown>): CreateAccountResponse['user'] {
  const id = String(raw.id ?? '');
  const email = String(raw.email ?? '');
  const username = raw.username != null ? String(raw.username) : undefined;
  return {
    id,
    name: raw.name != null ? String(raw.name) : null,
    email,
    tenantId: String(raw.tenantId ?? raw.tenant_id ?? ''),
    status: raw.status != null ? String(raw.status) : null,
    ...(username ? { username } : {})
  };
}

function deriveUsername(email: string, explicit?: string): string {
  const trimmed = explicit?.trim();
  if (trimmed) {
    return trimmed.slice(0, 80);
  }
  const local = email.split('@')[0] ?? 'user';
  const safe = local.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80);
  return safe || 'user';
}

function tenantHeaders(tenantId?: string): { 'X-Tenant-Id'?: string } | undefined {
  const t = tenantId?.trim();
  if (!t) {
    return undefined;
  }
  return { 'X-Tenant-Id': t };
}

export const registerUser = async (body: RegisterInput): Promise<CreateAccountResponse> => {
  const headers = tenantHeaders(body.tenantId);
  const created = await createChatUser(
    {
      role: 'CLIENT',
      email: body.email,
      username: deriveUsername(body.email, body.username),
      name: body.name
    },
    { headers: tenantHeaders(body.tenantId) }
  );
  const root = pickRecord(created) ?? {};
  const token = typeof root.token === 'string' ? root.token : '';
  const nestedUser = pickRecord(root.user);
  const userSource = nestedUser ?? root;
  return { token, user: mapToAuthUser(userSource) };
};

export const loginUser = async (body: LoginInput): Promise<CreateAccountResponse> => {
  const headers = tenantHeaders(body.tenantId);
  const users = await apiService.get<unknown>(API_PATHS.CHAT.USERS, { headers }).then((raw) => {
    if (Array.isArray(raw)) {
      return raw;
    }
    if (raw && typeof raw === 'object' && 'data' in raw && Array.isArray((raw as { data: unknown }).data)) {
      return (raw as { data: unknown[] }).data;
    }
    return [];
  });
  const lower = body.email.toLowerCase();
  const found = users
    .map((u) => pickRecord(u))
    .find((u) => u && String(u.email ?? '').toLowerCase() === lower);
  if (!found) {
    throw new Error('No chat user found for this email.');
  }
  return { token: '', user: mapToAuthUser(found) };
};
