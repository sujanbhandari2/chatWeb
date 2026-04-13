import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Navigate, useNavigate } from 'react-router-dom';
import { AdminRoutes } from '../../constants/admin.constants';
import { adminLoginSchema, type AdminLoginFormValues } from '../../schemas/admin.schemas';
import { useAdminLoginMutation } from '../../services/admin.service';
import { useAdminAuthStore } from '../../store/useAdminAuthStore';
import { pickBearerToken } from '../../types/admin.types';
import './admin-shell.css';

export function AdminLoginView(): JSX.Element {
  const token = useAdminAuthStore((s) => s.token);
  const sessionHydrated = useAdminAuthStore((s) => s.sessionHydrated);
  const navigate = useNavigate();
  const loginMut = useAdminLoginMutation();
  const [credentialError, setCredentialError] = useState('');

  const {
    register,
    handleSubmit,
    formState: { errors }
  } = useForm<AdminLoginFormValues>({
    resolver: zodResolver(adminLoginSchema),
    defaultValues: { email: '', password: '' }
  });

  if (sessionHydrated && token?.trim()) {
    return <Navigate to={AdminRoutes.CLIENTS} replace />;
  }

  if (!sessionHydrated) {
    return (
      <div className="admin-login-page">
        <p style={{ color: '#94a3b8' }}>Loading…</p>
      </div>
    );
  }

  return (
    <div className="admin-login-page">
      <div className="admin-login-card">
        <h1>Admin sign in</h1>
        <p className="admin-shell__muted">Use your admin JWT to manage clients and API keys.</p>
        <form
          className="admin-form-grid"
          onSubmit={handleSubmit(async (values) => {
            setCredentialError('');
            try {
              const res = await loginMut.mutateAsync(values);
              if (!pickBearerToken(res)) {
                setCredentialError('Server did not return a token.');
                return;
              }
              navigate(AdminRoutes.CLIENTS, { replace: true });
            } catch {
              /* toast from service */
            }
          })}
        >
          <input {...register('email')} type="email" autoComplete="username" placeholder="Email" />
          {errors.email && <p className="admin-error">{errors.email.message}</p>}
          <input
            {...register('password')}
            type="password"
            autoComplete="current-password"
            placeholder="Password"
          />
          {errors.password && <p className="admin-error">{errors.password.message}</p>}
          {credentialError ? <p className="admin-error">{credentialError}</p> : null}
          <button type="submit" disabled={loginMut.isPending}>
            {loginMut.isPending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
