import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { provisionUserSchema, type ProvisionUserInput } from '../../schemas/auth.schemas';
import { useProvisionUserMutation } from '../../services/auth.service';
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
  return 'Could not start chat';
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
      email: ''
    }
  });

  useEffect(() => {
    reset((prev) => ({
      ...prev,
      companyId: defaultCompanyId
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
      <button type="submit" disabled={widgetMissingTenant || mutation.isPending}>
        {mutation.isPending ? 'Starting…' : 'Open chat'}
      </button>
      {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
    </form>
  );
}
