import { useChatRuntimeContext } from '../../hooks/ChatRuntimeContext';
import type { WidgetSocketConnectionStatus } from '../../types/chat-runtime.types';

const STATUS_DOT_CLASS: Record<WidgetSocketConnectionStatus, string> = {
  inactive: 'widget-socket-status-bar__dot--inactive',
  connecting: 'widget-socket-status-bar__dot--pending',
  connected: 'widget-socket-status-bar__dot--live',
  reconnecting: 'widget-socket-status-bar__dot--pending',
  disconnected: 'widget-socket-status-bar__dot--off',
  error: 'widget-socket-status-bar__dot--error'
};

const STATUS_LABEL: Record<WidgetSocketConnectionStatus, string> = {
  inactive: 'Realtime off',
  connecting: 'Connecting…',
  connected: 'Connected',
  reconnecting: 'Reconnecting…',
  disconnected: 'Disconnected',
  error: 'Connection error'
};

/** Thin status strip for Socket.IO in the embedded widget (reads `ChatRuntimeContext`). */
export function WidgetSocketStatusBar(): JSX.Element {
  const { socketConnection } = useChatRuntimeContext();
  const { status, detail } = socketConnection;
  const title = detail ? `${STATUS_LABEL[status]} — ${detail}` : STATUS_LABEL[status];

  return (
    <div className="widget-socket-status-bar" role="status" aria-live="polite" title={title}>
      <span className={`widget-socket-status-bar__dot ${STATUS_DOT_CLASS[status]}`} aria-hidden />
      <span className="widget-socket-status-bar__label">{STATUS_LABEL[status]}</span>
    </div>
  );
}
