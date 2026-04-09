import type { ReactNode } from 'react';
import type { WidgetInitConfig } from '../../schemas/widget.schemas';
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
  widgetMissingTenant: boolean;
};

/** Login/register placeholder when the user is not signed in. */
export function WidgetUnauthenticatedContent({
  widgetMissingTenant
}: WidgetUnauthenticatedContentProps): JSX.Element {
  return (
    <div className="auth-shell auth-shell--widget">
      <div className="auth-card">
        <h1>Healthcare Chat</h1>
        <p className="auth-subtitle">
          Register uses <code>tenantId</code>, name, and email. Login uses a UUID <code>tenantId</code> and email,
          matching server Zod schemas.
        </p>

        {widgetMissingTenant && (
          <p className="error-banner">
            Missing <code>tenantId</code>. Your host sets the default in <code>src/config/widget.config.ts</code>, or
            customers can pass <code>tenantId</code> (or <code>tenant</code>) on the widget URL. API and socket URLs are
            not customer-configurable.
          </p>
        )}

        <div>
          <h3>User is not authenticated and missing token or user</h3>
        </div>

        {/* <AuthForm widgetMode widgetConfig={...} widgetMissingTenant={widgetMissingTenant} /> */}
      </div>
    </div>
  );
}
