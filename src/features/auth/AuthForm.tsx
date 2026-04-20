import { useEffect, useState } from 'react';
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

function RegisterInfoPanel(): JSX.Element {
  return (
    <div className="auth-form auth-form--info">
      <p>
        Tenant accounts are created by your Vitafy administrator. If you already have an email and
        password, switch to <strong>Login</strong>.
      </p>
    </div>
  );
}

function LoginFields({
  defaultTenantId,
  hideTenant,
  lockTenant,
  disabled
}: {
  defaultTenantId: string;
  hideTenant: boolean;
  lockTenant: boolean;
  disabled: boolean;
}): JSX.Element {
  const mutation = useLoginMutation();
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
            placeholder="Tenant ID (optional, embed routing)"
            disabled={disabled}
            readOnly={lockTenant}
          />
          {errors.tenantId && <p className="error-banner">{errors.tenantId.message}</p>}
        </>
      )}
      {hideTenant && <input type="hidden" {...register('tenantId')} />}
      <input {...register('email')} placeholder="Email" type="email" required disabled={disabled} />
      {errors.email && <p className="error-banner">{errors.email.message}</p>}
      <input
        {...register('password')}
        placeholder="Password"
        type="password"
        required
        minLength={8}
        autoComplete="current-password"
        disabled={disabled}
      />
      {errors.password && <p className="error-banner">{errors.password.message}</p>}
      <button type="submit" disabled={disabled || mutation.isPending}>
        {mutation.isPending ? 'Signing in...' : 'Login'}
      </button>
      {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
    </form>
  );
}

export function AuthForm({ widgetMode = false, widgetConfig, widgetMissingTenant }: AuthFormProps): JSX.Element {
  const [mode, setMode] = useState<'register' | 'login'>('login');
  const hideTenant = Boolean(widgetMode && widgetConfig?.backend?.hideTenantField);
  const lockTenant = Boolean(
    widgetMode && (widgetConfig?.backend?.lockTenant || widgetConfig?.backend?.hideTenantField)
  );
  const defaultTenantId =
    widgetMode && widgetConfig?.backend?.tenantId?.trim() ? widgetConfig.backend.tenantId.trim() : '';

  return (
    <>
      <div className="auth-mode-switch">
        <button
          className={mode === 'register' ? 'active' : ''}
          onClick={() => setMode('register')}
          type="button"
          disabled={widgetMissingTenant}
        >
          Register
        </button>
        <button
          className={mode === 'login' ? 'active' : ''}
          onClick={() => setMode('login')}
          type="button"
          disabled={widgetMissingTenant}
        >
          Login
        </button>
      </div>

      {mode === 'register' ? (
        <RegisterInfoPanel />
      ) : (
        <LoginFields
          defaultTenantId={defaultTenantId}
          hideTenant={hideTenant}
          lockTenant={lockTenant}
          disabled={widgetMissingTenant}
        />
      )}
    </>
  );
}
