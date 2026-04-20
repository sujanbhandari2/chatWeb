import { API_PATHS } from '../constants/api.constant';
import { apiService } from '../lib/api-service';
import { listChatUsers } from './chat.api';
import type { TenantUser } from '../types/chat';

/** Matches Chat API `CreateUserDto`. */
export type CreateTenantUserBody = {
  providerId: string;
  providerUserId: string;
  email: string;
  name?: string;
};

/** `POST /api/v1/chat/users` — `X-Api-Key` from axios (no separate company header). */
export const createTenantUser = (body: CreateTenantUserBody): Promise<unknown> => {
  const payload: Record<string, string> = {
    providerId: body.providerId.trim(),
    providerUserId: body.providerUserId.trim(),
    email: body.email.trim()
  };
  const name = body.name?.trim();
  if (name) {
    payload.name = name;
  }
  return apiService.post<unknown>(API_PATHS.CHAT.USERS, payload);
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function mapChatUserToTenantUser(u: Record<string, unknown>): TenantUser {
  const idRaw = u.id ?? u.user_id ?? u.userId;
  const id = idRaw != null && idRaw !== '' ? String(idRaw) : '';
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
