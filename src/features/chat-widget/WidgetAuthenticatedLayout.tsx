import { WidgetInitConfigProvider } from '../../contexts/config-provider';
import { ChatRuntimeProvider } from '../../hooks/ChatRuntimeContext';
import { WidgetPanelType } from '../../types/chat';
import type { WidgetAuthenticatedLayoutProps } from '../../types/widget-app.types';
import { WidgetSocketStatusBar } from './WidgetSocketStatusBar';
import { wrapWidgetContent } from './widget-shell';

export function WidgetAuthenticatedLayout({
  config,
  runtime,
  headerLabel,
  overlayVisible,
  selectedConversationId,
  currentPanel,
  user,
  sidebar,
  thread
}: WidgetAuthenticatedLayoutProps): JSX.Element {
  return wrapWidgetContent(
    config,
    <ChatRuntimeProvider value={runtime}>
      <WidgetInitConfigProvider value={config}>
        <div
          className={`chat-app-shell chat-app-shell--widget${
            overlayVisible ? ' chat-app-shell--widget-chat' : ''
          }`}
        >
          <WidgetSocketStatusBar />
          <aside
            className="left-rail left-rail--widget-full"
            aria-hidden={Boolean(selectedConversationId && currentPanel === WidgetPanelType.CHATS)}
          >
            {sidebar}
          </aside>
          {thread}
        </div>
      </WidgetInitConfigProvider>
    </ChatRuntimeProvider>,
    headerLabel,
    user
  );
}
