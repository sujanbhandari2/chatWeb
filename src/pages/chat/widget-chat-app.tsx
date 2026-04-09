import { WidgetChat } from '../../features/widget/WidgetChat';
import { defaultWidgetInitConfig, type WidgetInitConfig } from '../../schemas/widget.schemas';
import { useAuthStore } from '../../store/useAuthStore';
import { useChatSelectors } from '../../hooks/useChatSelectors';
import { WidgetInitConfigProvider } from '../../contexts/config-provider';
import { ChatRuntimeProvider } from '../../hooks/ChatRuntimeContext';
import { useChatRuntime } from '../../hooks/useChatRuntime';
import { ChatSidebar } from './chat-app/ChatSidebar';
import { ChatThreadView } from './chat-app/ChatThreadView';

export type WidgetChatAppProps = {
  widgetConfig?: WidgetInitConfig;
};

/** Chat app for the embed: session, lists, and thread inside the floating widget. */
export default function WidgetChatApp({ widgetConfig }: WidgetChatAppProps): JSX.Element {
  const resolvedWidgetConfig = widgetConfig ?? defaultWidgetInitConfig;
  const runtime = useChatRuntime(resolvedWidgetConfig);
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const sessionHydrated = useAuthStore((s) => s.sessionHydrated);

  const widgetMissingTenant = Boolean(!resolvedWidgetConfig.backend?.tenantId?.trim());

  const { widgetRailPane, selectedConversationId } = useChatSelectors((s) => ({
    widgetRailPane: s.widgetRailPane,
    selectedConversationId: s.selectedConversationId,
  }));

  const wrapInWidget = (node: JSX.Element, panelHeaderCenterText?: string): JSX.Element => (
    <WidgetChat config={resolvedWidgetConfig} panelHeaderCenterText={panelHeaderCenterText}>
      {node}
    </WidgetChat>
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
    return wrapInWidget(
      <div className="auth-shell auth-shell--widget">
        <div className="auth-card">
          <h1>Healthcare Chat</h1>
          <p className="auth-subtitle">Restoring your session...</p>
        </div>
      </div>
    );
  }

  if (!token || !user) {
    return wrapInWidget(
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
              customers can pass <code>tenantId</code> (or <code>tenant</code>) on the widget URL. API and socket URLs
              are not customer-configurable.
            </p>
          )}

          <div>
            <h3>
              User is not authenticated and missing token or user
            </h3>
          </div>

          {/* <AuthForm
            widgetMode
            widgetConfig={resolvedWidgetConfig}
            widgetMissingTenant={widgetMissingTenant}
          /> */}
        </div>
      </div>
    );
  }

  return (
    <ChatRuntimeProvider value={runtime}>
      {wrapInWidget(
        <WidgetInitConfigProvider value={resolvedWidgetConfig}>
          <div
            className={`chat-app-shell chat-app-shell--widget${
              chatOverlayOpen ? ' chat-app-shell--widget-chat' : ''
            }`}
          >
            <aside
              className="left-rail left-rail--widget-full"
              aria-hidden={Boolean(selectedConversationId && widgetRailPane === 'chats')}
            >
              <ChatSidebar />
            </aside>
            <ChatThreadView />
          </div>
        </WidgetInitConfigProvider>,
        panelHeaderLabel
      )}
    </ChatRuntimeProvider>
  );
}
