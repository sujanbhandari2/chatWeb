import { zodResolver } from '@hookform/resolvers/zod';
import { useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link, useLocation, useParams } from 'react-router-dom';
import { toast } from '../../common/ui/Toaster';
import { AdminRoutes } from '../../constants/admin.constants';
import {
  createAdminApiKeySchema,
  type CreateAdminApiKeyFormValues
} from '../../schemas/admin.schemas';
import {
  useAdminTenantApiKeysQuery,
  useCreateAdminTenantApiKeyMutation,
  useRevokeAdminTenantApiKeyMutation
} from '../../services/admin.service';
import {
  parseAdminApiKeyFromCreateResponse,
  parseAdminApiKeyRow,
  unwrapAdminList
} from '../../types/admin.types';
import { parseAdminCreateApiKeyHeaderValue } from '../../utils/chat-api-key.utils';
import type { AdminApiKeyRow } from '../../types/admin.types';
import { copyTextToClipboard } from '../../utils/clipboard.utils';

type LocationState = { name?: string; email?: string };

function shortenForList(value: string, head = 14, tail = 10): string {
  if (value.length <= head + tail + 3) {
    return value;
  }
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

async function copyWithToast(label: string, text: string): Promise<void> {
  try {
    await copyTextToClipboard(text);
    toast(`${label} copied to clipboard`);
  } catch {
    toast('Copy failed — check browser permissions');
  }
}

export function AdminTenantApiKeysView(): JSX.Element {
  const { userId = '' } = useParams<{ userId: string }>();
  const location = useLocation();
  const state = (location.state ?? {}) as LocationState;
  const title = state.name?.trim() || `User ${userId}`;

  const { data, isLoading, isError } = useAdminTenantApiKeysQuery(userId);
  const createMut = useCreateAdminTenantApiKeyMutation(userId);
  const revokeMut = useRevokeAdminTenantApiKeyMutation(userId);

  const rows = useMemo(
    () => unwrapAdminList<AdminApiKeyRow>(data ?? [], parseAdminApiKeyRow),
    [data]
  );

  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  /** Plaintext secrets only known right after create (server list usually omits them). */
  const [rowSecrets, setRowSecrets] = useState<Record<string, string>>({});

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
        <Link to={AdminRoutes.TENANTS}>← Tenants</Link>
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
            const headerValue = parseAdminCreateApiKeyHeaderValue(res);
            const createdRow = parseAdminApiKeyFromCreateResponse(res);
            if (headerValue) {
              setRevealedSecret(headerValue);
              if (createdRow?.id) {
                setRowSecrets((prev) => ({ ...prev, [createdRow.id]: headerValue }));
              }
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
          <h2>Copy this credential now</h2>
          <p className="admin-shell__muted" style={{ marginTop: 0 }}>
            Store this credential; the browser sends it as the{' '}
            <code style={{ fontSize: '0.9em' }}>X-Api-Key</code> header (same id:secret value below). This value will
            not be shown again—store it in your secrets manager.
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
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
            <button
              type="button"
              className="admin-btn-ghost"
              onClick={() => void copyWithToast('X-Api-Key value', revealedSecret)}
            >
              Copy X-Api-Key value
            </button>
            <button type="button" className="admin-btn-ghost" onClick={() => setRevealedSecret(null)}>
              Dismiss
            </button>
          </div>
        </div>
      ) : null}

      <div className="admin-panel">
        <h2>Existing keys</h2>
        {isLoading ? <p className="admin-shell__muted">Loading…</p> : null}
        {isError ? (
          <p className="admin-error" style={{ color: '#b91c1c' }}>
            Could not load keys (check tenant id and permissions).
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
                <th>Credential</th>
                <th>Scopes</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const secret = rowSecrets[row.id] ?? row.accessKey ?? null;
                const preview = row.keyPreview ?? null;
                const copyValue = secret ?? preview;
                const display = secret
                  ? shortenForList(secret)
                  : preview
                    ? shortenForList(preview, 24, 12)
                    : '—';

                return (
                <tr key={row.id}>
                  <td>{row.name ?? '—'}</td>
                  <td>
                    <code
                      style={{
                        fontSize: '0.82rem',
                        background: '#f1f5f9',
                        padding: '0.2rem 0.4rem',
                        borderRadius: 4,
                        wordBreak: 'break-all'
                      }}
                    >
                      {display}
                    </code>
                  </td>
                  <td>{row.scopes?.join(', ') || '—'}</td>
                  <td>{row.expiresAt ?? '—'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button
                      type="button"
                      className="admin-btn-ghost"
                      style={{ marginRight: '0.35rem' }}
                      disabled={!copyValue}
                      title={copyValue ?? undefined}
                      onClick={() => {
                        if (copyValue) {
                          void copyWithToast('X-Api-Key value', copyValue);
                        }
                      }}
                    >
                      Copy
                    </button>
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
                          void (async (): Promise<void> => {
                            await revokeMut.mutateAsync(row.id);
                            setRowSecrets((prev) => {
                              const next = { ...prev };
                              delete next[row.id];
                              return next;
                            });
                          })();
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              )})}
            </tbody>
          </table>
        ) : null}
      </div>
    </>
  );
}
