import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { ADMIN_RECENT_CLIENTS_KEY, AdminRoutes } from '../../constants/admin.constants';
import {
  createAdminClientSchema,
  type CreateAdminClientFormValues
} from '../../schemas/admin.schemas';
import { useCreateAdminClientMutation, useDeleteAdminClientMutation } from '../../services/admin.service';
import type { AdminClient } from '../../types/admin.types';
import { extractAdminClientFromCreateResponse, parseAdminClient } from '../../types/admin.types';

function readStoredClients(): AdminClient[] {
  try {
    const raw = sessionStorage.getItem(ADMIN_RECENT_CLIENTS_KEY);
    if (!raw) {
      return [];
    }
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) {
      return [];
    }
    return arr.map((x) => parseAdminClient(x)).filter((c): c is AdminClient => c !== null);
  } catch {
    return [];
  }
}

function persistClients(list: AdminClient[]): void {
  try {
    sessionStorage.setItem(ADMIN_RECENT_CLIENTS_KEY, JSON.stringify(list));
  } catch {
    /* ignore */
  }
}

export function AdminClientsView(): JSX.Element {
  const [clients, setClients] = useState<AdminClient[]>(readStoredClients);
  const createMut = useCreateAdminClientMutation();
  const deleteMut = useDeleteAdminClientMutation();

  useEffect(() => {
    persistClients(clients);
  }, [clients]);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors }
  } = useForm<CreateAdminClientFormValues>({
    resolver: zodResolver(createAdminClientSchema),
    defaultValues: { name: '', email: '', password: '' }
  });

  return (
    <>
      <h1>Clients</h1>
      <p className="admin-shell__muted">
        Create merchant accounts for the chat platform. There is no &quot;list all clients&quot; route in the API yet —
        this table remembers clients you create in this browser (session storage).
      </p>

      <div className="admin-panel">
        <h2>New client</h2>
        <form
          className="admin-form-grid"
          onSubmit={handleSubmit(async (values) => {
            const res = await createMut.mutateAsync(values);
            const parsed = extractAdminClientFromCreateResponse(res, {
              name: values.name,
              email: values.email
            });
            if (parsed) {
              setClients((prev) => {
                const rest = prev.filter((c) => c.id !== parsed.id);
                return [parsed, ...rest];
              });
            }
            reset({ name: '', email: '', password: '' });
          })}
        >
          <input {...register('name')} placeholder="Company / client name" maxLength={200} />
          {errors.name && <p className="admin-error" style={{ color: '#b91c1c' }}>{errors.name.message}</p>}
          <input {...register('email')} type="email" placeholder="Client login email" />
          {errors.email && <p className="admin-error" style={{ color: '#b91c1c' }}>{errors.email.message}</p>}
          <input {...register('password')} type="password" placeholder="Initial password (min 8)" />
          {errors.password && <p className="admin-error" style={{ color: '#b91c1c' }}>{errors.password.message}</p>}
          <button type="submit" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create client'}
          </button>
        </form>
      </div>

      <div className="admin-panel">
        <h2>Clients</h2>
        {clients.length === 0 ? (
          <p className="admin-shell__muted" style={{ margin: 0 }}>
            No clients recorded yet.
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
              {clients.map((c) => (
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
                        if (!window.confirm(`Delete client “${c.name}”? This cannot be undone.`)) {
                          return;
                        }
                        void (async (): Promise<void> => {
                          await deleteMut.mutateAsync(c.id);
                          setClients((prev) => prev.filter((x) => x.id !== c.id));
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
