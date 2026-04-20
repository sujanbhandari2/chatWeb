/// <reference types="vite/client" />

import type { WidgetInitConfig } from './schemas/widget.schemas';

interface ImportMetaEnv {
  /**
   * Widget base config: `development` | `staging` | `production`, or demo presets
   * `custom` | `dark` | `brand` | `full` (see `src/config/widget.config.ts`).
   */
  readonly VITE_WIDGET_PROFILE?: string;
  /** Injected from `package.json` version at build time (`vite.config.ts`). */
  readonly VITE_APP_VERSION: string;
  /** Vitafy chat: `accessKey:secretKey` — sole env source for `/v1/chat/*` (`X-Api-Key`) and Socket.IO `auth.apiKey`. */
  readonly VITE_WIDGET_ACCESS_KEY?: string;
}

declare global {
  interface Window {
    /**
     * Optional embed overrides before the widget bundle loads.
     * Applied: **layout / interaction**, and **`backend.tenantId` / `lockTenant` / `hideTenantField` / `tenantJwt`**.
     * Ignored from here: `backend.apiUrl`, `socketUrl`, timeouts, plus `uiElements`, `colors`, `typography`, `a11y`,
     * `features`, `app`, `zIndex`, `debug` (use `src/config/widget.config.ts`).
     */
    __HEALTHCHAT_WIDGET_CONFIG__?: Partial<WidgetInitConfig>;
  }
}

export {};
