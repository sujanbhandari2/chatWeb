export type AdminLoginResponse = {
  token: string;
  id: string;
  email: string;
  name: string;
};

export type AdminProfile = {
  id: string;
  email: string;
  name: string;
  createdAt: string;
};

/** Public tenant row from admin CRUD (`api_doc.md`). */
export type AdminTenant = {
  id: string;
  email: string;
  name: string;
  settings: Record<string, unknown>;
  createdAt: string;
};

export type AdminTenantDeleted = {
  deleted: true;
};

/** Listed API key (no secret). Shape may include extra fields from the backend. */
export type AdminApiKeyRow = {
  id: string;
  name?: string | null;
  accessKey?: string | null;
  secretKey?: string | null;
  scopes?: string[];
  expiresAt?: string | null;
  createdAt?: string;
  revokedAt?: string | null;
};

/** Create-key response: secret shown once per `api_doc.md`. */
export type AdminCreateApiKeyResult = AdminApiKeyRow & {
  secret?: string;
  secretKey?: string;
};
