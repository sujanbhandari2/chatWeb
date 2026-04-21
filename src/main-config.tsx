import React from 'react';
import ReactDOM from 'react-dom/client';
import { AppProviders } from './app/providers';
import { WidgetConfigView } from './pages/config/WidgetConfigView';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppProviders>
      <WidgetConfigView />
    </AppProviders>
  </React.StrictMode>
);
