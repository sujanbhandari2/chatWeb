import React from 'react';
import ReactDOM from 'react-dom/client';
import { AppProviders } from './app/providers';
import ChatAppView from './pages/chat/ChatAppView';
import { applyWidgetRuntimeFromConfig, getWidgetInitConfig } from './utils/widget-runtime.utils';
import './widget.theme.css';
import './styles.css';

document.documentElement.classList.add('healthchat-widget-entry');
document.body.classList.add('healthchat-widget-entry');

const widgetConfig = getWidgetInitConfig();
applyWidgetRuntimeFromConfig(widgetConfig);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppProviders>
      <ChatAppView widgetConfig={widgetConfig} />
    </AppProviders>
  </React.StrictMode>
);
