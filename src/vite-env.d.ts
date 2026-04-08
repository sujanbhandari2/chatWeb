/// <reference types="vite/client" />

import type { WidgetInitConfig } from './schemas/widget.schemas';

declare global {
  interface Window {
    /** Set before the widget bundle loads (optional); merged with URL query params. */
    __HEALTHCHAT_WIDGET_CONFIG__?: Partial<WidgetInitConfig>;
  }
}

export {};
