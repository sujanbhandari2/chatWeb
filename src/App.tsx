import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import type { WidgetInitConfig } from './schemas/widget.schemas';
import WidgetChatApp from './pages/chat/widget-chat-app';
import { AdminApp } from './pages/admin/AdminApp';

export type AppProps = {
  widgetConfig?: WidgetInitConfig;
};

/** Main SPA: widget chat at `/`, Vitafy admin console at `/admin`. */
function viteRouterBasename(): string | undefined {
  const raw = import.meta.env.BASE_URL;
  const trimmed = raw.endsWith('/') ? raw.slice(0, -1) : raw;
  return trimmed === '' ? undefined : trimmed;
}

export default function App(props: AppProps = {}): JSX.Element {
  return (
    <BrowserRouter basename={viteRouterBasename()}>
      <Routes>
        <Route path="/admin/*" element={<AdminApp />} />
        <Route path="/" element={<WidgetChatApp widgetConfig={props.widgetConfig} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
