/// <reference types="vite/client" />

import type { WidgetInitConfig } from './schemas/widget.schemas';

interface ImportMetaEnv {
  /**
   * Widget base config: `development` | `staging` | `production`, or demo presets
   * `custom` | `dark` | `brand` | `full` (see `src/config/widget.config.ts`).
   */
  readonly VITE_WIDGET_PROFILE?: string;
}

declare global {
  interface Window {
    /**
     * Optional embed overrides before the widget bundle loads.
     * Applied: **layout / interaction**, and **`backend.tenantId` / `lockTenant` / `hideTenantField`** only.
     * Ignored from here: `backend.apiUrl`, `socketUrl`, timeouts, plus `uiElements`, `colors`, `typography`, `a11y`,
     * `zIndex`, `debug` (use `src/config/widget.config.ts`).
     */
    __HEALTHCHAT_WIDGET_CONFIG__?: Partial<WidgetInitConfig>;
  }
}

export {};
