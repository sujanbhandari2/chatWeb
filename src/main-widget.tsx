import React from 'react';
import ReactDOM from 'react-dom/client';
import { AppProviders } from './app/providers';
import ChatAppView from './pages/chat/ChatAppView';
import { applyRuntimeApiOverrides } from './utils/runtime-endpoints.utils';
import { getWidgetInitConfig } from './utils/widget-runtime.utils';
import './styles.css';

document.documentElement.classList.add('healthchat-widget-entry');
document.body.classList.add('healthchat-widget-entry');

const widgetConfig = getWidgetInitConfig();
applyRuntimeApiOverrides({
  apiUrl: widgetConfig.apiUrl,
  socketUrl: widgetConfig.socketUrl
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppProviders>
      <ChatAppView widgetMode widgetConfig={widgetConfig} />
    </AppProviders>
  </React.StrictMode>
);
