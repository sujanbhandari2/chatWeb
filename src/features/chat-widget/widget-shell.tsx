import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { WIDGET_PUBLIC_PATHS } from '../../constants/widget.constants';
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
          This chat widget must receive a valid <strong>API credential</strong> (<code>accessKey:secretKey</code> as{' '}
          <code>X-Api-Key</code>). Set <code>backend.accessKey</code> plus <code>backend.secretKey</code>, or a combined{' '}
          <code>accessKey</code> string, pass query params (dev only), or use <code>VITE_WIDGET_ACCESS_KEY</code> /{' '}
          <code>VITE_WIDGET_SECRET_KEY</code> in <code>.env</code> for local widget builds.
        </p>
        <p className="auth-subtitle" style={{ marginTop: '0.75rem' }}>
          <Link to={WIDGET_PUBLIC_PATHS.EMBED_DOCS} style={{ color: '#2563eb' }}>
            Public integration guide
          </Link>{' '}
          · repo: <code>docs/WIDGET_WEBSITE.md</code>
        </p>
      </div>
    </div>
  );
}

/** One-step user creation (`POST /v1/user/users`) before chat UI loads. */
export function WidgetUnauthenticatedContent({
  config,
  widgetMissingTenant
}: WidgetUnauthenticatedContentProps): JSX.Element {
  return (
    <div className="auth-shell auth-shell--widget">
      <div className="auth-card">
        <h1>Healthcare Chat</h1>
        <p className="auth-subtitle" style={{ marginBottom: '0.5rem' }}>
          Enter your details once—we call the user API and open your conversations.
        </p>
        <AuthForm widgetMode={true} widgetConfig={config} widgetMissingTenant={widgetMissingTenant} />
      </div>
    </div>
  );
}
