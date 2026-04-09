import { WidgetAuthenticatedLayout } from '../../features/chat-widget/WidgetAuthenticatedLayout';
import { WidgetSessionLoadingShell } from '../../features/chat-widget/WidgetSessionLoadingShell';
import { WidgetUnauthenticatedShell } from '../../features/chat-widget/WidgetUnauthenticatedShell';
import { useWidgetConfig } from '../../hooks/useWidgetConfig';
import type { WidgetChatAppProps } from '../../types/widget-app.types';
import { ChatSidebar } from './chat-app/ChatSidebar';
import { ChatThreadView } from './chat-app/ChatThreadView';

export type { WidgetChatAppProps } from '../../types/widget-app.types';

/**
 * Embedded widget entry: session → auth shells → authenticated chat (sidebar + thread).
 */
export default function WidgetChatApp({ widgetConfig }: WidgetChatAppProps): JSX.Element {
  const {
    config,
    runtime,
    token,
    user,
    sessionHydrated,
    currentPanel,
    selectedConversationId,
    isMissingTenant,
    headerLabel,
    overlayVisible
  } = useWidgetConfig(widgetConfig);

  if (!sessionHydrated) {
    return <WidgetSessionLoadingShell config={config} />;
  }

  if (!token || !user) {
    return <WidgetUnauthenticatedShell config={config} isMissingTenant={isMissingTenant} />;
  }

  return (
    <WidgetAuthenticatedLayout
      config={config}
      runtime={runtime}
      headerLabel={headerLabel}
      overlayVisible={overlayVisible}
      selectedConversationId={selectedConversationId}
      currentPanel={currentPanel}
      sidebar={<ChatSidebar />}
      thread={<ChatThreadView />}
    />
  );
}
