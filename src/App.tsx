import ChatAppView, { type ChatAppViewProps } from './pages/chat/ChatAppView';

export type AppProps = ChatAppViewProps;

/** Root app: widget-style messenger (same entry as embed). */
export default function App(props: ChatAppViewProps = {}): JSX.Element {
  return <ChatAppView widgetConfig={props.widgetConfig} />;
}
