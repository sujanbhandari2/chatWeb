import type { ReactNode } from 'react';
import type { WidgetInitConfig } from '../../schemas/widget.schemas';
import { WidgetChat } from './ChatWidget';
import { AuthForm } from '../auth/AuthForm';

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

/** No launcher actions — static message inside the widget panel. */
export function WidgetUnauthorizedContent(): JSX.Element {
  return (
    <div className="auth-shell auth-shell--widget">
      <div className="auth-card" style={{ borderColor: '#fecdd3', boxShadow: '0 20px 48px rgba(185, 28, 28, 0.12)' }}>
        <h1>Unauthorized</h1>
        <p className="auth-subtitle">
          This chat widget must receive an <strong>access key</strong> so it can call the API as your client. Add{' '}
          <code>backend.accessKey</code> (or <code>backend.apiKey</code>) in your embed config, pass{' '}
          <code>?accessKey=…</code> on the iframe URL (dev only recommended), or set <code>VITE_API_KEY</code> for local
          development.
        </p>
        <p className="auth-subtitle" style={{ marginTop: '0.75rem' }}>
          See <code>docs/WIDGET_WEBSITE.md</code> for full website integration steps.
        </p>
      </div>
    </div>
  );
}

/** Login/register placeholder when the user is not signed in. */
export function WidgetUnauthenticatedContent({
  config,
  widgetMissingTenant
}: WidgetUnauthenticatedContentProps): JSX.Element {
  return (
    <div className="auth-shell auth-shell--widget">
      <div className="auth-card">
        <h1>Healthcare Chat</h1>
        <p className="auth-subtitle">
          Register creates a <strong>chat user</strong> (name, email, optional username). Login finds an existing chat
          user by email. The host must already supply an <strong>access key</strong> (<code>backend.accessKey</code> or{' '}
          <code>backend.apiKey</code>) so requests include <code>X-Api-Key</code>. Optionally set{' '}
          <code>backend.tenantId</code> for <code>X-Tenant-Id</code>.
        </p>

        {!config.backend?.tenantId?.trim() && (
          <p className="error-banner" style={{ borderColor: '#e2e8f0', background: '#f8fafc', color: '#475569' }}>
            Optional: set <code>backend.tenantId</code> or <code>?tenantId=</code> if your API expects{' '}
            <code>X-Tenant-Id</code>.
          </p>
        )}

        <AuthForm widgetMode={true} widgetConfig={config} widgetMissingTenant={widgetMissingTenant} />
      </div>
    </div>
  );
}
