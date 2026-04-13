import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import type { WidgetInitConfig } from './schemas/widget.schemas';
import WidgetChatApp from './pages/chat/widget-chat-app';
import { AdminRoutes } from './constants/admin.constants';
import { AdminAuthGuard } from './pages/admin/AdminAuthGuard';
import { AdminClientApiKeysView } from './pages/admin/AdminClientApiKeysView';
import { AdminClientsView } from './pages/admin/AdminClientsView';
import { AdminLayout } from './pages/admin/AdminLayout';
import { AdminLoginView } from './pages/admin/AdminLoginView';

export type AppProps = {
  widgetConfig?: WidgetInitConfig;
};

/** Root: admin console (`/admin/*`) or embedded chat widget (`/*`). */
export default function App(props: AppProps = {}): JSX.Element {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/admin/login" element={<AdminLoginView />} />
        <Route path="/admin" element={<AdminAuthGuard />}>
          <Route element={<AdminLayout />}>
            <Route index element={<Navigate to={AdminRoutes.CLIENTS} replace />} />
            <Route path="clients" element={<AdminClientsView />} />
            <Route path="clients/:clientId/keys" element={<AdminClientApiKeysView />} />
          </Route>
        </Route>
        <Route path="/*" element={<WidgetChatApp widgetConfig={props.widgetConfig} />} />
      </Routes>
    </BrowserRouter>
  );
}
