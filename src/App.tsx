import ChatAppView, { type ChatAppViewProps } from './pages/chat/ChatAppView';
import type { WidgetInitConfig } from './schemas/widget.schemas';

export type AppProps = ChatAppViewProps;

/** @deprecated Prefer importing `ChatAppView` from `pages/chat/ChatAppView`. */
export default function App(props: { widgetMode?: boolean; widgetConfig?: WidgetInitConfig } = {}): JSX.Element {
  return <ChatAppView {...props} />;
}
