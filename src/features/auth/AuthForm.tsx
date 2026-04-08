import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import {
  loginSchema,
  registerSchema,
  type LoginInput,
  type RegisterInput
} from '../../schemas/auth.schemas';
import { useLoginMutation, useRegisterMutation } from '../../services/auth.service';
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

function RegisterFields({
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
  const mutation = useRegisterMutation();
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors }
  } = useForm<RegisterInput>({
    resolver: zodResolver(registerSchema),
    defaultValues: { tenantId: defaultTenantId, name: '', email: '' }
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
      {hideTenant ? (
        <input type="hidden" {...register('tenantId')} />
      ) : (
        <input
          {...register('tenantId')}
          placeholder="Tenant ID"
          required
          disabled={disabled}
          readOnly={lockTenant}
        />
      )}
      {errors.tenantId && <p className="error-banner">{errors.tenantId.message}</p>}
      <input {...register('name')} placeholder="Name" required maxLength={120} disabled={disabled} />
      {errors.name && <p className="error-banner">{errors.name.message}</p>}
      <input {...register('email')} placeholder="Email" type="email" required disabled={disabled} />
      {errors.email && <p className="error-banner">{errors.email.message}</p>}
      <button type="submit" disabled={disabled || mutation.isPending}>
        {mutation.isPending ? 'Creating account...' : 'Create account'}
      </button>
      {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
    </form>
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
    defaultValues: { tenantId: defaultTenantId, email: '' }
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
      {hideTenant ? (
        <input type="hidden" {...register('tenantId')} />
      ) : (
        <input
          {...register('tenantId')}
          placeholder="Tenant ID (UUID)"
          required
          disabled={disabled}
          readOnly={lockTenant}
        />
      )}
      {errors.tenantId && <p className="error-banner">{errors.tenantId.message}</p>}
      <input {...register('email')} placeholder="Email" type="email" required disabled={disabled} />
      {errors.email && <p className="error-banner">{errors.email.message}</p>}
      <button type="submit" disabled={disabled || mutation.isPending}>
        {mutation.isPending ? 'Signing in...' : 'Login'}
      </button>
      {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
    </form>
  );
}

export function AuthForm({ widgetMode = false, widgetConfig, widgetMissingTenant }: AuthFormProps): JSX.Element {
  const [mode, setMode] = useState<'register' | 'login'>('register');
  const hideTenant = Boolean(widgetMode && widgetConfig?.hideTenantField);
  const lockTenant = Boolean(widgetMode && (widgetConfig?.lockTenant || widgetConfig?.hideTenantField));
  const defaultTenantId =
    widgetMode && widgetConfig?.tenantId?.trim() ? widgetConfig.tenantId.trim() : '';

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
        <RegisterFields
          defaultTenantId={defaultTenantId}
          hideTenant={hideTenant}
          lockTenant={lockTenant}
          disabled={widgetMissingTenant}
        />
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
