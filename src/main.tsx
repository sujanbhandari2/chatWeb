import React from 'react';
import ReactDOM from 'react-dom/client';
import { bootstrapWidgetResolvedConfig } from './bootstrap/main';
import { AppProviders } from './app/providers';
import App from './App';
import './styles.css';

const widgetConfig = bootstrapWidgetResolvedConfig();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppProviders>
      <App widgetConfig={widgetConfig} />
    </AppProviders>
  </React.StrictMode>
);
