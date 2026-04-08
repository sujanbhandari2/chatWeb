import { ChatWidgetShell } from '../../features/widget/ChatWidgetShell';
import { defaultWidgetInitConfig, type WidgetInitConfig } from '../../schemas/widget.schemas';
import { useAuthStore } from '../../store/useAuthStore';
import { useChatSelectors } from '../../hooks/useChatSelectors';
import { AuthForm } from '../../features/auth/AuthForm';
import { ChatRuntimeProvider } from '../../hooks/ChatRuntimeContext';
import { useChatRuntime } from '../../hooks/useChatRuntime';
import { ChatSidebar } from './messenger/ChatSidebar';
import { ChatThreadView } from './messenger/ChatThreadView';

export type ChatAppShellProps = {
  widgetConfig?: WidgetInitConfig;
};

/** Authenticated chat layout: widget chrome, sidebar, and main thread. */
export default function ChatAppShell({ widgetConfig }: ChatAppShellProps): JSX.Element {
  const runtime = useChatRuntime();
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const sessionHydrated = useAuthStore((s) => s.sessionHydrated);

  const resolvedWidgetConfig = widgetConfig ?? defaultWidgetInitConfig;
  const widgetMissingTenant = Boolean(!resolvedWidgetConfig.backend?.tenantId?.trim());

  const { widgetRailPane, selectedConversationId } = useChatSelectors((s) => ({
    widgetRailPane: s.widgetRailPane,
    selectedConversationId: s.selectedConversationId,
  }));

  const shellWrap = (node: JSX.Element, panelHeaderCenterText?: string): JSX.Element => (
    <ChatWidgetShell config={resolvedWidgetConfig} panelHeaderCenterText={panelHeaderCenterText}>
      {node}
    </ChatWidgetShell>
  );

  const panelHeaderLabel =
    widgetRailPane === 'people'
      ? 'People'
      : widgetRailPane === 'new-group'
        ? 'New group'
        : widgetRailPane === 'edit-group'
          ? 'Edit group'
          : 'Chats';

  const chatOverlayOpen = Boolean(selectedConversationId) && widgetRailPane === 'chats';

  if (!sessionHydrated) {
    return shellWrap(
      <div className="auth-shell auth-shell--widget">
        <div className="auth-card">
          <h1>Healthcare Messenger</h1>
          <p className="auth-subtitle">Restoring your session...</p>
        </div>
      </div>
    );
  }

  if (!token || !user) {
    return shellWrap(
      <div className="auth-shell auth-shell--widget">
        <div className="auth-card">
          <h1>Healthcare Messenger</h1>
          <p className="auth-subtitle">
            Register uses <code>tenantId</code>, name, and email. Login uses a UUID <code>tenantId</code> and email,
            matching server Zod schemas.
          </p>

          {widgetMissingTenant && (
            <p className="error-banner">
              Missing <code>tenantId</code>. Set it in your widget build profile (
              <code>src/config/widget.config.ts</code>) or pass <code>tenantId</code> (or <code>tenant</code>) in the
              embed URL / <code>window.__HEALTHCHAT_WIDGET_CONFIG__.backend.tenantId</code>. API URLs and branding
              still come only from your build.
            </p>
          )}

          <AuthForm
            widgetMode
            widgetConfig={resolvedWidgetConfig}
            widgetMissingTenant={widgetMissingTenant}
          />
        </div>
      </div>
    );
  }

  return (
    <ChatRuntimeProvider value={runtime}>
      {shellWrap(
        <div
          className={`messenger-shell messenger-shell--widget${
            chatOverlayOpen ? ' messenger-shell--widget-chat' : ''
          }`}
        >
          <aside
            className="left-rail left-rail--widget-full"
            aria-hidden={Boolean(selectedConversationId && widgetRailPane === 'chats')}
          >
            <ChatSidebar />
          </aside>
          <ChatThreadView />
        </div>,
        panelHeaderLabel
      )}
    </ChatRuntimeProvider>
  );
}
