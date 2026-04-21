import React from 'react';
import ReactDOM from 'react-dom/client';
import { bootstrapWidgetResolvedConfig } from './bootstrap/main';
import { AppProviders } from './app/providers';
import App from './App';
import './widget.theme.css';
import './styles.css';

const widgetConfig = bootstrapWidgetResolvedConfig();
const brandDocClass = `${widgetConfig.styling.classPrefix}-doc-entry`;

document.documentElement.classList.add('healthchat-widget-entry', 'vcw-doc-entry', brandDocClass);
document.body.classList.add('healthchat-widget-entry', 'vcw-doc-entry', brandDocClass);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppProviders>
      <App widgetConfig={widgetConfig} />
    </AppProviders>
  </React.StrictMode>
);
