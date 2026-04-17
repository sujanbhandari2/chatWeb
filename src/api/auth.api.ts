import type { ProvisionUserInput } from '../schemas/auth.schemas';
import type { CreateAccountResponse } from '../types/chat';
import { createClientUser } from './users.api';

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
 * Creates the chat end-user via `POST /api/v1/user/users` (embed uses `X-Api-Key` + optional company).
 * Response may omit JWT; chat still works with API key + resolved user id.
 */
export const provisionUser = async (body: ProvisionUserInput): Promise<CreateAccountResponse> => {
  const created = await createClientUser({
    companyId: body.companyId.trim(),
    email: body.email.trim(),
    name: body.name.trim(),
    externalId: body.externalId.trim()
  });
  const root = pickRecord(created) ?? {};
  const token =
    typeof root.token === 'string'
      ? root.token
      : typeof root.access_token === 'string'
        ? root.access_token
        : typeof root.accessToken === 'string'
          ? root.accessToken
          : '';
  const userSource = pickUserRecordFromClientCreateResponse(created);
  const user = mapToAuthUser(userSource);
  if (!user.id?.trim()) {
    throw new Error('User id missing in API response');
  }
  return { token, user };
};
