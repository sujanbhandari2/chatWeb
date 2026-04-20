import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { provisionUserSchema, type ProvisionUserInput } from '../../schemas/auth.schemas';
import { useProvisionUserMutation } from '../../services/auth.service';

export type AuthFormProps = {
  widgetMissingTenant: boolean;
};

function authErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return 'Could not start chat';
}

export function AuthForm({ widgetMissingTenant }: AuthFormProps): JSX.Element {
  const mutation = useProvisionUserMutation();

  const {
    register,
    handleSubmit,
    formState: { errors }
  } = useForm<ProvisionUserInput>({
    resolver: zodResolver(provisionUserSchema),
    defaultValues: {
      providerId: '',
      providerUserId: '',
      email: '',
      name: ''
    }
  });

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
      <input
        {...register('providerId')}
        placeholder="Provider id (e.g. widget, auth0, internal)"
        required
        maxLength={120}
        autoComplete="off"
        disabled={widgetMissingTenant}
      />
      {errors.providerId && <p className="error-banner">{errors.providerId.message}</p>}
      <input
        {...register('providerUserId')}
        placeholder="Provider user id (your system id for this person)"
        required
        maxLength={256}
        autoComplete="off"
        disabled={widgetMissingTenant}
      />
      {errors.providerUserId && <p className="error-banner">{errors.providerUserId.message}</p>}
      <input {...register('email')} placeholder="Email" type="email" required disabled={widgetMissingTenant} />
      {errors.email && <p className="error-banner">{errors.email.message}</p>}
      <input {...register('name')} placeholder="Display name (optional)" maxLength={120} disabled={widgetMissingTenant} />
      {errors.name && <p className="error-banner">{errors.name.message}</p>}
      <button type="submit" disabled={widgetMissingTenant || mutation.isPending}>
        {mutation.isPending ? 'Starting…' : 'Open chat'}
      </button>
      {mutation.isError && <p className="error-banner">{authErrorMessage(mutation.error)}</p>}
    </form>
  );
}
