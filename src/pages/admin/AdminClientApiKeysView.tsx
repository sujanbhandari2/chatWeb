import { zodResolver } from '@hookform/resolvers/zod';
import { useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link, useLocation, useParams } from 'react-router-dom';
import { AdminRoutes } from '../../constants/admin.constants';
import {
  createAdminApiKeySchema,
  type CreateAdminApiKeyFormValues
} from '../../schemas/admin.schemas';
import {
  useAdminClientApiKeysQuery,
  useCreateAdminClientApiKeyMutation,
  useRevokeAdminClientApiKeyMutation
} from '../../services/admin.service';
import {
  parseAdminApiKeyRow,
  pickApiKeyPlaintext,
  unwrapAdminList
} from '../../types/admin.types';
import type { AdminApiKeyRow } from '../../types/admin.types';

type LocationState = { name?: string; email?: string };

export function AdminClientApiKeysView(): JSX.Element {
  const { clientId = '' } = useParams<{ clientId: string }>();
  const location = useLocation();
  const state = (location.state ?? {}) as LocationState;
  const title = state.name?.trim() || `Client ${clientId}`;

  const { data, isLoading, isError } = useAdminClientApiKeysQuery(clientId);
  const createMut = useCreateAdminClientApiKeyMutation(clientId);
  const revokeMut = useRevokeAdminClientApiKeyMutation(clientId);

  const rows = useMemo(
    () => unwrapAdminList<AdminApiKeyRow>(data ?? [], parseAdminApiKeyRow),
    [data]
  );

  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors }
  } = useForm<CreateAdminApiKeyFormValues>({
    resolver: zodResolver(createAdminApiKeySchema),
    defaultValues: { name: '', scopesText: '', expiresAt: '' }
  });

  return (
    <>
      <p style={{ margin: '0 0 0.5rem' }}>
        <Link to={AdminRoutes.CLIENTS}>← Clients</Link>
      </p>
      <h1>API keys</h1>
      <p className="admin-shell__muted">
        {title}
        {state.email ? ` · ${state.email}` : ''}
      </p>

      <div className="admin-panel">
        <h2>Create API key</h2>
        <form
          className="admin-form-grid"
          onSubmit={handleSubmit(async (values) => {
            const scopes = values.scopesText
              ?.split(',')
              .map((s) => s.trim())
              .filter(Boolean);
            const res = await createMut.mutateAsync({
              name: values.name?.trim() || undefined,
              scopes: scopes && scopes.length > 0 ? scopes : undefined,
              expiresAt: values.expiresAt?.trim() || undefined
            });
            const secret = pickApiKeyPlaintext(res);
            if (secret) {
              setRevealedSecret(secret);
            }
            reset({ name: '', scopesText: '', expiresAt: '' });
          })}
        >
          <input {...register('name')} placeholder="Key label (optional)" maxLength={120} />
          {errors.name && <p className="admin-error" style={{ color: '#b91c1c' }}>{errors.name.message}</p>}
          <input {...register('scopesText')} placeholder="Scopes (comma-separated, optional)" />
          <input {...register('expiresAt')} placeholder="Expires at ISO date (optional)" />
          <button type="submit" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create key'}
          </button>
        </form>
      </div>

      {revealedSecret ? (
        <div className="admin-panel" style={{ border: '2px solid #2563eb' }}>
          <h2>Copy this secret now</h2>
          <p className="admin-shell__muted" style={{ marginTop: 0 }}>
            It will not be shown again. Store it in your secrets manager.
          </p>
          <pre
            style={{
              padding: '0.75rem',
              background: '#0f172a',
              color: '#e2e8f0',
              borderRadius: 8,
              overflow: 'auto',
              fontSize: '0.85rem'
            }}
          >
            {revealedSecret}
          </pre>
          <button type="button" className="admin-btn-ghost" onClick={() => setRevealedSecret(null)}>
            Dismiss
          </button>
        </div>
      ) : null}

      <div className="admin-panel">
        <h2>Existing keys</h2>
        {isLoading ? <p className="admin-shell__muted">Loading…</p> : null}
        {isError ? (
          <p className="admin-error" style={{ color: '#b91c1c' }}>
            Could not load keys (check client id and permissions).
          </p>
        ) : null}
        {!isLoading && !isError && rows.length === 0 ? (
          <p className="admin-shell__muted" style={{ margin: 0 }}>
            No keys yet.
          </p>
        ) : null}
        {!isLoading && rows.length > 0 ? (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Scopes</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.name ?? '—'}</td>
                  <td>{row.scopes?.join(', ') || '—'}</td>
                  <td>{row.expiresAt ?? '—'}</td>
                  <td>
                    {row.revokedAt ? (
                      <span style={{ color: '#64748b' }}>Revoked</span>
                    ) : (
                      <button
                        type="button"
                        className="admin-btn-ghost admin-btn-danger"
                        disabled={revokeMut.isPending}
                        onClick={() => {
                          if (!window.confirm('Revoke this API key?')) {
                            return;
                          }
                          void revokeMut.mutateAsync(row.id);
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>
    </>
  );
}
