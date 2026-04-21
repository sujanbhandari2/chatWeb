import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import {
  adminCreateApiKeySchema,
  adminCreateTenantSchema,
  adminUpdateTenantSchema,
  type AdminCreateApiKeyFormValues,
  type AdminCreateTenantFormValues,
  type AdminUpdateTenantFormValues
} from '../../schemas/admin-tenants.schemas';
import {
  useAdminTenantsQuery,
  useCreateApiKeyMutation,
  useCreateTenantMutation,
  useDeleteTenantMutation,
  useRevokeApiKeyMutation,
  useTenantApiKeysQuery,
  useUpdateTenantMutation
} from '../../services/admin.service';
import type { AdminCreateApiKeyResult, AdminTenant } from '../../types/admin.types';
import '../../common/layout/admin-layout.css';

function formatNewApiKeyCredential(data: AdminCreateApiKeyResult): string {
  const access = typeof data.accessKey === 'string' ? data.accessKey : '';
  const secret =
    typeof data.secret === 'string'
      ? data.secret
      : typeof (data as { secretKey?: string }).secretKey === 'string'
        ? (data as { secretKey: string }).secretKey
        : '';
  if (access && secret) {
    return `${access}:${secret}`;
  }
  return JSON.stringify(data, null, 2);
}

export function TenantsConsole(): JSX.Element {
  const { data: tenants = [], isLoading, isError, error } = useAdminTenantsQuery();
  const createTenant = useCreateTenantMutation();
  const updateTenant = useUpdateTenantMutation();
  const deleteTenant = useDeleteTenantMutation();
  const createKey = useCreateApiKeyMutation();
  const revokeKey = useRevokeApiKeyMutation();

  const [createOpen, setCreateOpen] = useState(false);
  const [editTenant, setEditTenant] = useState<AdminTenant | null>(null);
  const [keysTenant, setKeysTenant] = useState<AdminTenant | null>(null);
  const [secretText, setSecretText] = useState<string | null>(null);

  const keysQuery = useTenantApiKeysQuery(keysTenant?.id ?? null);

  const createForm = useForm<AdminCreateTenantFormValues>({
    resolver: zodResolver(adminCreateTenantSchema),
    defaultValues: { name: '', email: '', password: '' }
  });

  const editForm = useForm<AdminUpdateTenantFormValues>({
    resolver: zodResolver(adminUpdateTenantSchema),
    defaultValues: { name: '', email: '', password: '' }
  });

  const keyForm = useForm<AdminCreateApiKeyFormValues>({
    resolver: zodResolver(adminCreateApiKeySchema),
    defaultValues: { name: '', expiresAt: '' }
  });

  useEffect(() => {
    if (createOpen) {
      createForm.reset({ name: '', email: '', password: '' });
    }
  }, [createOpen, createForm]);

  useEffect(() => {
    if (editTenant) {
      editForm.reset({
        name: editTenant.name,
        email: editTenant.email,
        password: ''
      });
    }
  }, [editTenant, editForm]);

  useEffect(() => {
    if (keysTenant) {
      keyForm.reset({ name: '', expiresAt: '' });
    }
  }, [keysTenant, keyForm]);

  if (keysTenant) {
    return (
      <div className="va-admin-panel" style={{ maxWidth: '56rem' }}>
        <div className="va-admin-toolbar" style={{ marginBottom: '0.75rem' }}>
          <button
            type="button"
            className="va-admin-btn"
            onClick={() => {
              setKeysTenant(null);
              setSecretText(null);
            }}
          >
            ← Back
          </button>
        </div>

        <h2 style={{ marginBottom: '0.25rem' }}>API keys</h2>
        <p className="va-admin-muted" style={{ marginBottom: '1rem' }}>
          Tenant <strong>{keysTenant.name}</strong> · <code>{keysTenant.id}</code>
        </p>
        <p className="va-admin-muted" style={{ marginBottom: '1rem' }}>
          Use <code>X-Api-Key: accessKey:secretKey</code> on chat routes. The secret is shown only once when a key is
          created.
        </p>

        {secretText !== null && (
          <div style={{ marginBottom: '1rem' }}>
            <h3 style={{ margin: 0 }}>Save this credential</h3>
            <p className="va-admin-muted">It will not be shown again. Format for <code>X-Api-Key</code> header:</p>
            <textarea className="va-admin-secret-box" readOnly value={secretText} rows={4} />
            <div className="va-admin-toolbar" style={{ marginBottom: 0 }}>
              <button
                type="button"
                className="va-admin-btn"
                onClick={() => {
                  void navigator.clipboard.writeText(secretText);
                }}
              >
                Copy
              </button>
              <button
                type="button"
                className="va-admin-btn va-admin-btn--primary"
                onClick={() => setSecretText(null)}
              >
                Done
              </button>
            </div>
          </div>
        )}

        <form
          onSubmit={keyForm.handleSubmit(async (values) => {
            try {
              const body: { name?: string; expiresAt?: string } = {};
              if (values.name?.trim()) {
                body.name = values.name.trim();
              }
              if (values.expiresAt?.trim()) {
                body.expiresAt = values.expiresAt.trim();
              }
              const result = await createKey.mutateAsync({ tenantId: keysTenant.id, body });
              setSecretText(formatNewApiKeyCredential(result));
              keyForm.reset({ name: '', expiresAt: '' });
            } catch {
              /* mutation.isError below */
            }
          })}
          style={{ marginBottom: '1rem' }}
        >
          <div className="va-admin-field">
            <label htmlFor="va-nk-name">Key name (optional)</label>
            <input id="va-nk-name" {...keyForm.register('name')} />
          </div>
          <div className="va-admin-field">
            <label htmlFor="va-nk-exp">Expires at ISO (optional)</label>
            <input id="va-nk-exp" {...keyForm.register('expiresAt')} placeholder="2030-01-01T00:00:00.000Z" />
          </div>
          <button type="submit" className="va-admin-btn va-admin-btn--primary" disabled={createKey.isPending}>
            {createKey.isPending ? 'Creating…' : 'Create key'}
          </button>
          {createKey.isError && (
            <p className="error-banner" style={{ marginTop: 8 }}>
              {createKey.error instanceof Error ? createKey.error.message : 'Create key failed'}
            </p>
          )}
        </form>

        {keysQuery.isLoading && <p className="va-admin-muted">Loading keys…</p>}
        {keysQuery.data && keysQuery.data.length === 0 && !keysQuery.isLoading && (
          <p className="va-admin-muted">No keys yet.</p>
        )}
        {keysQuery.data && keysQuery.data.length > 0 && (
          <div className="va-admin-table-wrap">
            <table className="va-admin-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Access key</th>
                  <th>Secret key</th>
                  <th>Scopes</th>
                  <th>Expires</th>
                  <th>Created</th>
                  <th>Revoked</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {keysQuery.data.map((k) => (
                  <tr key={k.id}>
                    <td>
                      {k.name ?? '—'}
                    </td>
                    <td>
                      <code className="va-admin-muted">{k.accessKey ?? '—'}</code>
                    </td>
                    <td>
                      <code className="va-admin-muted">{k.secretKey ?? '—'}</code>
                    </td>
                    <td>
                      <code className="va-admin-muted">{k.scopes?.join(', ') ?? '—'}</code>
                    </td>
                    <td>
                      <code className="va-admin-muted">{k.expiresAt ?? '—'}</code>
                    </td>
                    <td>
                      <code className="va-admin-muted">{k.createdAt ?? '—'}</code>
                    </td>
                    <td>
                      <code className="va-admin-muted">{k.revokedAt ?? '—'}</code>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="va-admin-btn va-admin-btn--danger"
                        disabled={revokeKey.isPending}
                        onClick={() => {
                          if (window.confirm('Revoke this API key?')) {
                            void revokeKey.mutateAsync({ tenantId: keysTenant.id, keyId: k.id });
                          }
                        }}
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="va-admin-panel" style={{ maxWidth: '56rem' }}>
      <h2>Tenants</h2>
      <p className="va-admin-muted" style={{ marginBottom: '1rem' }}>
        Matches <code>GET/POST/PATCH/DELETE /api/v1/admin/tenants</code> and tenant API keys in{' '}
        <code>api_doc.md</code>.
      </p>

      <div className="va-admin-toolbar">
        <button type="button" className="va-admin-btn va-admin-btn--primary" onClick={() => setCreateOpen(true)}>
          New tenant
        </button>
      </div>

      {isLoading && <p className="va-admin-muted">Loading…</p>}
      {isError && (
        <p className="error-banner">{error instanceof Error ? error.message : 'Failed to load tenants'}</p>
      )}

      {!isLoading && !isError && (
        <div className="va-admin-table-wrap">
          <table className="va-admin-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Id</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tenants.length === 0 ? (
                <tr>
                  <td colSpan={5} className="va-admin-muted">
                    No tenants yet.
                  </td>
                </tr>
              ) : (
                tenants.map((t) => (
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td>{t.email}</td>
                    <td>
                      <code className="va-admin-muted">{t.id}</code>
                    </td>
                    <td>{new Date(t.createdAt).toLocaleString()}</td>
                    <td>
                      <div className="va-admin-table-actions">
                        <button type="button" className="va-admin-btn" onClick={() => setKeysTenant(t)}>
                          API keys
                        </button>
                        <button type="button" className="va-admin-btn" onClick={() => setEditTenant(t)}>
                          Edit
                        </button>
                        <button
                          type="button"
                          className="va-admin-btn va-admin-btn--danger"
                          disabled={deleteTenant.isPending}
                          onClick={() => {
                            if (window.confirm(`Soft-delete tenant “${t.name}” (${t.email})?`)) {
                              void deleteTenant.mutateAsync(t.id);
                            }
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {createOpen && (
        <div className="va-admin-modal-overlay" role="presentation" onClick={() => setCreateOpen(false)}>
          <div
            className="va-admin-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="va-create-tenant-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id="va-create-tenant-title">Create tenant</h3>
            <form
              onSubmit={createForm.handleSubmit(async (values) => {
                await createTenant.mutateAsync(values);
                setCreateOpen(false);
              })}
            >
              <div className="va-admin-field">
                <label htmlFor="va-ct-name">Name</label>
                <input id="va-ct-name" {...createForm.register('name')} autoComplete="organization" />
                {createForm.formState.errors.name && (
                  <p className="error-banner">{createForm.formState.errors.name.message}</p>
                )}
              </div>
              <div className="va-admin-field">
                <label htmlFor="va-ct-email">Email</label>
                <input id="va-ct-email" type="email" {...createForm.register('email')} autoComplete="off" />
                {createForm.formState.errors.email && (
                  <p className="error-banner">{createForm.formState.errors.email.message}</p>
                )}
              </div>
              <div className="va-admin-field">
                <label htmlFor="va-ct-pass">Password</label>
                <input id="va-ct-pass" type="password" {...createForm.register('password')} autoComplete="new-password" />
                {createForm.formState.errors.password && (
                  <p className="error-banner">{createForm.formState.errors.password.message}</p>
                )}
              </div>
              {createTenant.isError && (
                <p className="error-banner">
                  {createTenant.error instanceof Error ? createTenant.error.message : 'Create failed'}
                </p>
              )}
              <div className="va-admin-modal-actions">
                <button type="button" className="va-admin-btn" onClick={() => setCreateOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="va-admin-btn va-admin-btn--primary" disabled={createTenant.isPending}>
                  {createTenant.isPending ? 'Creating…' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {editTenant && (
        <div className="va-admin-modal-overlay" role="presentation" onClick={() => setEditTenant(null)}>
          <div
            className="va-admin-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="va-edit-tenant-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id="va-edit-tenant-title">Edit tenant</h3>
            <p className="va-admin-muted" style={{ marginBottom: '0.75rem' }}>
              Tenant id <code>{editTenant.id}</code>. Leave password blank to keep the current password.
            </p>
            <form
              onSubmit={editForm.handleSubmit(async (values) => {
                const body: { name?: string; email?: string; password?: string } = {};
                const name = values.name?.trim() ?? '';
                const email = values.email?.trim() ?? '';
                const password = values.password?.trim() ?? '';
                if (name && name !== editTenant.name) {
                  body.name = name;
                }
                if (email && email !== editTenant.email) {
                  body.email = email;
                }
                if (password) {
                  body.password = password;
                }
                if (Object.keys(body).length === 0) {
                  editForm.setError('password', { type: 'manual', message: 'Change at least one field' });
                  return;
                }
                await updateTenant.mutateAsync({ id: editTenant.id, body });
                setEditTenant(null);
              })}
            >
              <div className="va-admin-field">
                <label htmlFor="va-et-name">Name</label>
                <input id="va-et-name" {...editForm.register('name')} />
                {editForm.formState.errors.name && (
                  <p className="error-banner">{editForm.formState.errors.name.message}</p>
                )}
              </div>
              <div className="va-admin-field">
                <label htmlFor="va-et-email">Email</label>
                <input id="va-et-email" type="email" {...editForm.register('email')} />
                {editForm.formState.errors.email && (
                  <p className="error-banner">{editForm.formState.errors.email.message}</p>
                )}
              </div>
              <div className="va-admin-field">
                <label htmlFor="va-et-pass">New password</label>
                <input id="va-et-pass" type="password" {...editForm.register('password')} autoComplete="new-password" />
                {editForm.formState.errors.password && (
                  <p className="error-banner">{editForm.formState.errors.password.message}</p>
                )}
              </div>
              <div className="va-admin-modal-actions">
                <button type="button" className="va-admin-btn" onClick={() => setEditTenant(null)}>
                  Cancel
                </button>
                <button type="submit" className="va-admin-btn va-admin-btn--primary" disabled={updateTenant.isPending}>
                  {updateTenant.isPending ? 'Saving…' : 'Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
