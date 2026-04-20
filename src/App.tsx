import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import type { WidgetInitConfig } from './schemas/widget.schemas';
import WidgetChatApp from './pages/chat/widget-chat-app';
import { AdminRoutes } from './constants/admin.constants';
import { AdminAuthGuard } from './pages/admin/AdminAuthGuard';
import { AdminTenantApiKeysView } from './pages/admin/AdminTenantApiKeysView';
import { AdminTenantsView } from './pages/admin/AdminTenantsView';
import { AdminLayout } from './pages/admin/AdminLayout';
import { AdminLoginView } from './pages/admin/AdminLoginView';
import WidgetEmbedDocsView from './pages/widget-docs/WidgetEmbedDocsView';
import { WIDGET_PUBLIC_PATHS } from './constants/widget.constants';

export type AppProps = {
  widgetConfig?: WidgetInitConfig;
};

/** Root: admin console (`/admin/*`) or embedded chat widget (`/*`). */
export default function App(props: AppProps = {}): JSX.Element {
  return (
    <BrowserRouter>
      <Routes>
        <Route path={WIDGET_PUBLIC_PATHS.EMBED_DOCS} element={<WidgetEmbedDocsView />} />
        <Route path="/admin/login" element={<AdminLoginView />} />
        <Route path="/admin" element={<AdminAuthGuard />}>
          <Route element={<AdminLayout />}>
            <Route index element={<Navigate to={AdminRoutes.TENANTS} replace />} />
            <Route path="tenants" element={<AdminTenantsView />} />
            <Route path="tenants/:userId/keys" element={<AdminTenantApiKeysView />} />
          </Route>
        </Route>
        <Route path="/*" element={<WidgetChatApp widgetConfig={props.widgetConfig} />} />
      </Routes>
    </BrowserRouter>
  );
}
