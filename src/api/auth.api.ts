import type { ProvisionUserInput } from '../schemas/auth.schemas';
import type { CreateAccountResponse } from '../types/chat';
import { createClientUser } from './users.api';

function withCompanyFallback(raw: Record<string, unknown>, companyId: string): Record<string, unknown> {
  const cid = pickCompanyId(raw);
  if (cid) {
    return raw;
  }
  return { ...raw, companyId };
}

function pickRecord(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function pickUserRecordFromClientCreateResponse(created: unknown): Record<string, unknown> {
  const root = pickRecord(created) ?? {};
  const directUser = pickRecord(root.user);
  if (directUser) {
    return directUser;
  }
  const data = pickRecord(root.data);
  if (data) {
    const nested = pickRecord(data.user);
    if (nested) {
      return nested;
    }
    if (data.id != null || data.email != null) {
      return data;
    }
  }
  return root;
}

function pickCompanyId(raw: Record<string, unknown>): string {
  return String(raw.companyId ?? raw.company_id ?? raw.tenantId ?? raw.tenant_id ?? '');
}

function mapToAuthUser(raw: Record<string, unknown>): CreateAccountResponse['user'] {
  const id = String(raw.id ?? '');
  const email = String(raw.email ?? '');
  return {
    id,
    name: raw.name != null ? String(raw.name) : null,
    email,
    companyId: pickCompanyId(raw),
    status: raw.status != null ? String(raw.status) : null
  };
}

/**
 * Creates the chat user via `POST /api/v1/chat/users` (embed: `X-Api-Key` + `X-Company-Id`).
 * Response may omit JWT; chat still works with API key + resolved user id.
 */
export const provisionUser = async (body: ProvisionUserInput): Promise<CreateAccountResponse> => {
  const companyId = body.companyId.trim();
  const created = await createClientUser(
    {
      email: body.email.trim(),
      name: body.name.trim()
    },
    companyId
  );
  const root = pickRecord(created) ?? {};
  const token =
    typeof root.token === 'string'
      ? root.token
      : typeof root.access_token === 'string'
        ? root.access_token
        : typeof root.accessToken === 'string'
          ? root.accessToken
          : '';
  const userSource = withCompanyFallback(pickUserRecordFromClientCreateResponse(created), companyId);
  const user = mapToAuthUser(userSource);
  if (!user.id?.trim()) {
    throw new Error('User id missing in API response');
  }
  return { token, user };
};
