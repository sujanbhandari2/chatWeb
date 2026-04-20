import { zodResolver } from '@hookform/resolvers/zod';
import type { ReactNode } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { registerOrGetChatUser } from '../../api/chat-users.api';
import type { WidgetInitConfig } from '../../schemas/widget.schemas';
import { useAuthStore } from '../../store/useAuthStore';
import type { AuthUser } from '../../types/chat';
import { WidgetChat } from './ChatWidget';

/** Wraps panel body content in the floating widget (launcher + panel). */
export function wrapWidgetContent(
  config: WidgetInitConfig,
  content: ReactNode,
  panelHeaderCenterText?: string
): JSX.Element {
  return (
    <WidgetChat config={config} panelHeaderCenterText={panelHeaderCenterText}>
      {content}
    </WidgetChat>
  );
}

/** Shown while persisted session is being restored. */
export function WidgetSessionLoadingContent(): JSX.Element {
  return (
    <div className="auth-shell auth-shell--widget">
      <div className="auth-card">
        <h1>Healthcare Chat</h1>
        <p className="auth-subtitle">Restoring your session...</p>
      </div>
    </div>
  );
}

export type WidgetUnauthenticatedContentProps = {
  config: WidgetInitConfig;
  widgetMissingTenant: boolean;
};

const widgetCreateUserSchema = z.object({
  providerId: z.string().trim().min(1, 'Provider id is required').max(64),
  providerUserId: z.string().trim().min(1, 'Provider user id is required').max(128),
  email: z.string().trim().email('Valid email required'),
  name: z.string().trim().max(120).optional()
});

type WidgetCreateUserFormValues = z.infer<typeof widgetCreateUserSchema>;

function buildAuthUserFromChatUser(row: {
  id: string;
  tenantId: string;
  email: string;
  name: string | null;
  status: string;
}): AuthUser {
  return {
    id: row.id,
    name: row.name ?? row.email,
    email: row.email,
    tenantId: row.tenantId,
    status: row.status
  };
}

/** Login/register placeholder when the user is not signed in. */
export function WidgetUnauthenticatedContent({
  config,
  widgetMissingTenant
}: WidgetUnauthenticatedContentProps): JSX.Element {
  const setSession = useAuthStore((s) => s.setSession);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting }
  } = useForm<WidgetCreateUserFormValues>({
    resolver: zodResolver(widgetCreateUserSchema),
    defaultValues: {
      providerId: 'widget',
      providerUserId: '',
      email: '',
      name: ''
    }
  });

  void widgetMissingTenant;

  return (
    <div className="auth-shell auth-shell--widget">
      <div className="auth-card">
        <h1>Vitafy Chat</h1>
        <p className="auth-subtitle">
          Create a chat user
        </p>
        <p className="auth-subtitle" style={{ fontSize: '0.85rem' }}>
          Realtime (Socket.IO) needs a tenant JWT in <code>handshake.auth.token</code>. If your session token is not a
          JWT, set <code>backend.tenantJwt</code> in the trusted widget init config (e.g. your dev profile in{' '}
          <code>widget.config.ts</code>).
        </p>

        <form
          className="auth-form"
          onSubmit={handleSubmit(async (values) => {
            const chatUser = await registerOrGetChatUser({
              providerId: values.providerId.trim(),
              providerUserId: values.providerUserId.trim(),
              email: values.email.trim(),
              name: values.name?.trim() || undefined
            });
            // Token is used as a session flag in the widget; chat routes use X-Api-Key instead of tenant JWT.
            setSession('chat-api-key', buildAuthUserFromChatUser(chatUser));
          })}
        >
          <input {...register('providerId')} placeholder="Provider id" />
          {errors.providerId && <p className="error-banner">{errors.providerId.message}</p>}

          <input {...register('providerUserId')} placeholder="Provider user id" />
          {errors.providerUserId && <p className="error-banner">{errors.providerUserId.message}</p>}

          <input {...register('email')} placeholder="Email" type="email" required />
          {errors.email && <p className="error-banner">{errors.email.message}</p>}

          <input {...register('name')} placeholder="Name" />
          {errors.name && <p className="error-banner">{errors.name.message}</p>}

          <button type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Creating…' : 'Create user'}
          </button>
        </form>
      </div>
    </div>
  );
}
