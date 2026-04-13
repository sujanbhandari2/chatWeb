import { listChatUsers } from './chat.api';
import type { TenantUser } from '../types/chat';

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function mapChatUserToTenantUser(u: Record<string, unknown>): TenantUser {
  const id = String(u.id ?? '');
  return {
    id,
    tenantId: String(u.tenantId ?? u.tenant_id ?? ''),
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
