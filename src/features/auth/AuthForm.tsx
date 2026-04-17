import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { provisionUserSchema, type ProvisionUserInput } from '../../schemas/auth.schemas';
import { useProvisionUserMutation } from '../../services/auth.service';
import type { WidgetInitConfig } from '../../schemas/widget.schemas';
import { WIDGET_EXTERNAL_ID_STORAGE_KEY } from '../../constants/session.constants';

export type AuthFormProps = {
  widgetMode?: boolean;
  widgetConfig?: WidgetInitConfig | null;
  widgetMissingTenant: boolean;
};

function authErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return 'Could not start chat';
}

function getOrCreateWidgetExternalId(): string {
  try {
    const existing = window.localStorage.getItem(WIDGET_EXTERNAL_ID_STORAGE_KEY);
    if (existing?.trim()) {
      return existing.trim();
    }
    const id =
      typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `ext_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
    window.localStorage.setItem(WIDGET_EXTERNAL_ID_STORAGE_KEY, id);
    return id;
  } catch {
    return `ext_${Date.now()}`;
  }
}

export function AuthForm({ widgetMode = false, widgetConfig, widgetMissingTenant }: AuthFormProps): JSX.Element {
  const mutation = useProvisionUserMutation();
  const hideTenant = Boolean(widgetMode && widgetConfig?.backend?.hideTenantField);
  const lockTenant = Boolean(
    widgetMode && (widgetConfig?.backend?.lockTenant || widgetConfig?.backend?.hideTenantField)
  );
  const defaultCompanyId =
    widgetMode && widgetConfig?.backend?.companyId?.trim() ? widgetConfig.backend.companyId.trim() : '';

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors }
  } = useForm<ProvisionUserInput>({
    resolver: zodResolver(provisionUserSchema),
    defaultValues: {
      companyId: defaultCompanyId,
      name: '',
      email: '',
      externalId: getOrCreateWidgetExternalId()
    }
  });

  useEffect(() => {
    reset((prev) => ({
      ...prev,
      companyId: defaultCompanyId,
      externalId: prev.externalId?.trim() || getOrCreateWidgetExternalId()
    }));
  }, [defaultCompanyId, reset]);

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
        <input type="hidden" {...register('companyId')} />
      ) : (
        <input
          {...register('companyId')}
          placeholder="Company ID"
          required
          disabled={widgetMissingTenant}
          readOnly={lockTenant}
        />
      )}
      {errors.companyId && <p className="error-banner">{errors.companyId.message}</p>}
      <input {...register('name')} placeholder="Name" required maxLength={120} disabled={widgetMissingTenant} />
      {errors.name && <p className="error-banner">{errors.name.message}</p>}
      <input {...register('email')} placeholder="Email" type="email" required disabled={widgetMissingTenant} />
      {errors.email && <p className="error-banner">{errors.email.message}</p>}
      <input type="hidden" {...register('externalId')} />
      {errors.externalId && <p className="error-banner">{errors.externalId.message}</p>}
      <button type="submit" disabled={widgetMissingTenant || mutation.isPending}>
        {mutation.isPending ? 'Starting…' : 'Open chat'}
      </button>
      {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
    </form>
  );
}
