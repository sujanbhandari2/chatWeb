import { Fragment, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { loginSchema, type LoginInput } from '../../schemas/auth.schemas';
import { useLoginMutation } from '../../services/auth.service';
import type { WidgetInitConfig } from '../../schemas/widget.schemas';

export type AuthFormProps = {
  widgetMode?: boolean;
  widgetConfig?: WidgetInitConfig | null;
  widgetMissingTenant: boolean;
};

function authErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return 'Authentication failed';
}

export function AuthForm({ widgetMode = false, widgetConfig, widgetMissingTenant }: AuthFormProps): JSX.Element {
  const mutation = useLoginMutation();
  const hideTenant = Boolean(widgetMode && widgetConfig?.backend?.hideTenantField);
  const lockTenant = Boolean(
    widgetMode && (widgetConfig?.backend?.lockTenant || widgetConfig?.backend?.hideTenantField)
  );
  const defaultTenantId =
    widgetMode && widgetConfig?.backend?.tenantId?.trim() ? widgetConfig.backend.tenantId.trim() : '';

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors }
  } = useForm<LoginInput>({
    resolver: zodResolver(loginSchema),
    defaultValues: { tenantId: defaultTenantId, email: '', password: '' }
  });

  useEffect(() => {
    reset((prev) => ({ ...prev, tenantId: defaultTenantId }));
  }, [defaultTenantId, reset]);

  return (
    <Fragment>
    <div className="auth-mode-switch" style={{ marginBottom: '0.75rem' }}>
      <span className="auth-mode-single">Tenant sign in</span>
    </div>
    <form
      className="auth-form"
      onSubmit={handleSubmit(async (data) => {
        try {
          await mutation.mutateAsync(data);
        } catch {
          /* mutation.error below */
        }
      })}
    >
      {!hideTenant && (
        <>
          <input
            {...register('tenantId')}
            placeholder="Tenant id (optional, embed routing)"
            disabled={widgetMissingTenant}
            readOnly={lockTenant}
          />
          {errors.tenantId && <p className="error-banner">{errors.tenantId.message}</p>}
        </>
      )}
      {hideTenant && <input type="hidden" {...register('tenantId')} />}
      <input {...register('email')} placeholder="Email" type="email" required disabled={widgetMissingTenant} />
      {errors.email && <p className="error-banner">{errors.email.message}</p>}
      <input
        {...register('password')}
        placeholder="Password"
        type="password"
        required
        minLength={8}
        autoComplete="current-password"
        disabled={widgetMissingTenant}
      />
      {errors.password && <p className="error-banner">{errors.password.message}</p>}
      <p className="auth-subtitle" style={{ fontSize: '0.85rem', marginTop: 0 }}>
        Uses <code>POST /api/v1/auth/tenant/login</code> per Vitafy API. Accounts are created in admin.
      </p>
      <button type="submit" disabled={widgetMissingTenant || mutation.isPending}>
        {mutation.isPending ? 'Signing in…' : 'Sign in'}
      </button>
      {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
    </form>
    </Fragment>
  );
}
