import { zodResolver } from '@hookform/resolvers/zod';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { ADMIN_RECENT_TENANTS_KEY, AdminRoutes } from '../../constants/admin.constants';
import {
  createAdminTenantSchema,
  type CreateAdminTenantFormValues
} from '../../schemas/admin.schemas';
import {
  adminKeys,
  useAdminTenantsQuery,
  useCreateAdminTenantMutation,
  useDeleteAdminTenantMutation
} from '../../services/admin.service';
import type { AdminTenant } from '../../types/admin.types';
import { parseAdminTenant } from '../../types/admin.types';

function readStoredTenants(): AdminTenant[] {
  try {
    const raw = sessionStorage.getItem(ADMIN_RECENT_TENANTS_KEY);
    if (!raw) {
      return [];
    }
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) {
      return [];
    }
    return arr.map((x) => parseAdminTenant(x)).filter((c): c is AdminTenant => c !== null);
  } catch {
    return [];
  }
}

function persistTenants(list: AdminTenant[]): void {
  try {
    sessionStorage.setItem(ADMIN_RECENT_TENANTS_KEY, JSON.stringify(list));
  } catch {
    /* ignore */
  }
}

export function AdminTenantsView(): JSX.Element {
  const qc = useQueryClient();
  const tenantsQuery = useAdminTenantsQuery();
  const createMut = useCreateAdminTenantMutation();
  const deleteMut = useDeleteAdminTenantMutation();

  const tenants: AdminTenant[] =
    tenantsQuery.data !== undefined ? tenantsQuery.data : readStoredTenants();

  useEffect(() => {
    if (tenantsQuery.data !== undefined) {
      persistTenants(tenantsQuery.data);
    }
  }, [tenantsQuery.data]);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors }
  } = useForm<CreateAdminTenantFormValues>({
    resolver: zodResolver(createAdminTenantSchema),
    defaultValues: { name: '', email: '', password: '' }
  });

  return (
    <>
      <h1>Tenants</h1>
      <p className="admin-shell__muted">
        Create tenant accounts for the chat platform. The list loads from{' '}
        <code>GET /api/v1/admin/tenants</code> when available; if that request fails, this page falls back to tenants
        remembered in this browser (session storage).
      </p>
      {tenantsQuery.isError ? (
        <p className="admin-shell__muted" style={{ color: '#b45309' }}>
          Could not refresh tenants from the server — showing session storage only.
        </p>
      ) : null}

      <div className="admin-panel">
        <h2>New tenant</h2>
        <form
          className="admin-form-grid"
          onSubmit={handleSubmit(async (values) => {
            await createMut.mutateAsync(values);
            reset({ name: '', email: '', password: '' });
          })}
        >
          <input {...register('name')} placeholder="Company / tenant name" maxLength={200} />
          {errors.name && <p className="admin-error" style={{ color: '#b91c1c' }}>{errors.name.message}</p>}
          <input {...register('email')} type="email" placeholder="Tenant login email" />
          {errors.email && <p className="admin-error" style={{ color: '#b91c1c' }}>{errors.email.message}</p>}
          <input {...register('password')} type="password" placeholder="Initial password (min 8)" />
          {errors.password && <p className="admin-error" style={{ color: '#b91c1c' }}>{errors.password.message}</p>}
          <button type="submit" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create tenant'}
          </button>
        </form>
      </div>

      <div className="admin-panel">
        <h2>Tenants</h2>
        {tenantsQuery.isPending && tenantsQuery.fetchStatus === 'fetching' && tenants.length === 0 ? (
          <p className="admin-shell__muted" style={{ margin: 0 }}>
            Loading tenants…
          </p>
        ) : tenants.length === 0 ? (
          <p className="admin-shell__muted" style={{ margin: 0 }}>
            No tenants recorded yet.
          </p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th />
                <th />
              </tr>
            </thead>
            <tbody>
              {tenants.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.email}</td>
                  <td>
                    <Link to={AdminRoutes.userKeys(c.id)} state={{ name: c.name, email: c.email }}>
                      API keys
                    </Link>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="admin-btn-ghost admin-btn-danger"
                      disabled={deleteMut.isPending}
                      onClick={() => {
                        if (!window.confirm(`Delete tenant “${c.name}”? This cannot be undone.`)) {
                          return;
                        }
                        void (async (): Promise<void> => {
                          await deleteMut.mutateAsync(c.id);
                          const next = tenants.filter((x) => x.id !== c.id);
                          persistTenants(next);
                          qc.setQueryData(adminKeys.tenants(), next);
                        })();
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
