import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { adminLoginSchema, type AdminLoginFormValues } from '../../schemas/admin.schemas';
import { useAdminLoginMutation } from '../../services/admin.service';
import '../../common/layout/admin-layout.css';

function authErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return 'Sign-in failed';
}

export function AdminLoginView(): JSX.Element {
  const mutation = useAdminLoginMutation();
  const {
    register,
    handleSubmit,
    formState: { errors }
  } = useForm<AdminLoginFormValues>({
    resolver: zodResolver(adminLoginSchema),
    defaultValues: { email: '', password: '' }
  });

  return (
    <div className="va-admin-root">
      <div className="va-admin-shell" style={{ justifyContent: 'center', alignItems: 'center', padding: '2rem' }}>
        <div className="va-admin-panel" style={{ maxWidth: '22rem', width: '100%' }}>
          <h2>Admin sign in</h2>
          <p style={{ marginBottom: '1.25rem' }}>Use your Vitafy admin credentials.</p>
          <form
            className="auth-form"
            onSubmit={handleSubmit(async (data) => {
              try {
                await mutation.mutateAsync(data);
              } catch {
                /* mutation.error */
              }
            })}
          >
            <input {...register('email')} type="email" placeholder="Email" required autoComplete="username" />
            {errors.email && <p className="error-banner">{errors.email.message}</p>}
            <input
              {...register('password')}
              type="password"
              placeholder="Password"
              required
              minLength={8}
              autoComplete="current-password"
            />
            {errors.password && <p className="error-banner">{errors.password.message}</p>}
            <button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? 'Signing in…' : 'Sign in'}
            </button>
            {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
          </form>
        </div>
      </div>
    </div>
  );
}
