import type { WidgetInitConfig } from './schemas/widget.schemas';
import WidgetChatApp from './pages/chat/widget-chat-app';

export type AppProps = {
  widgetConfig?: WidgetInitConfig;
};

/** Root app: full chat UI inside the floating widget. */
export default function App(props: AppProps = {}): JSX.Element {
  return <WidgetChatApp widgetConfig={props.widgetConfig} />;
}
