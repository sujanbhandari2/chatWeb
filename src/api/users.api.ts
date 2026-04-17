import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import { listChatUsers } from './chat.api';
import type { TenantUser } from '../types/chat';

export type CreateClientUserBody = {
  email: string;
  name?: string;
};

/** `POST /api/v1/chat/users` — requires `X-Company-Id` (sent here so it matches the provision form when tenant is editable). */
export const createClientUser = (body: CreateClientUserBody, companyId: string): Promise<unknown> =>
  apiService.post<unknown>(API_PATHS.CHAT.USERS, body, {
    headers: { 'X-Company-Id': companyId.trim() }
  });

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function mapChatUserToTenantUser(u: Record<string, unknown>): TenantUser {
  const id = String(u.id ?? '');
  return {
    id,
    companyId: String(u.companyId ?? u.company_id ?? u.tenantId ?? u.tenant_id ?? ''),
    name: u.name != null ? String(u.name) : null,
    email: String(u.email ?? ''),
    avatarUrl: u.avatarUrl != null ? String(u.avatarUrl) : null,
    status: u.status != null ? String(u.status) : null,
    createdAt: String(u.createdAt ?? u.created_at ?? new Date().toISOString()),
    isOnline: Boolean(u.isOnline ?? u.is_online)
  };
}

export const getTenantUsers = async (): Promise<TenantUser[]> => {
  const raw = await listChatUsers();
  return raw.filter(isRecord).map(mapChatUserToTenantUser);
};
