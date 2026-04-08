import type { WidgetInitConfig } from '../../schemas/widget.schemas';
import ChatAppShell from './ChatAppShell';

export type ChatAppViewProps = {
  widgetConfig?: WidgetInitConfig;
};

/** Embeddable widget entry: chat UI in widget shell. */
export default function ChatAppView({ widgetConfig }: ChatAppViewProps): JSX.Element {
  return <ChatAppShell widgetConfig={widgetConfig} />;
}
