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

/** Login/register placeholder when the user is not signed in. */
export function WidgetUnauthenticatedContent({
  config,
  widgetMissingTenant
}: WidgetUnauthenticatedContentProps): JSX.Element {
  return (
    <div className="auth-shell auth-shell--widget">
      <div className="auth-card">
        <h1>Vitafy Chat</h1>
        <p className="auth-subtitle">
          Sign in with tenant <strong>email</strong> and <strong>password</strong> (<code>POST /api/v1/auth/tenant/login</code>).
          Chat uses your tenant JWT plus the configured <code>X-Api-Key</code> for realtime and REST.
        </p>

        {widgetMissingTenant && (
          <p className="error-banner">
            Missing <code>tenantId</code> for embed routing. Set a default in <code>src/config/widget.config.ts</code> or
            pass <code>tenantId</code> on the widget URL. API and socket URLs come from the build profile only.
          </p>
        )}
        <AuthForm widgetMode={true} widgetConfig={config} widgetMissingTenant={widgetMissingTenant} />
      </div>
    </div>
  );
}
