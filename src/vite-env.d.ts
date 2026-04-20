/// <reference types="vite/client" />

import type { WidgetInitConfig } from './schemas/widget.schemas';

interface ImportMetaEnv {
  /** Optional: folded into widget `backend.companyId` / URL helpers only — not sent as `X-Company-Id`. */
  readonly VITE_WIDGET_COMPANY_ID?: string;
  /** @deprecated Alias read by `widget.html` for the same optional `backend` field. */
  readonly VITE_WIDGET_TENANT_ID?: string;
  /**
   * Widget base config: `development` | `staging` | `production`, or demo presets
   * `custom` | `dark` | `brand` | `full` (see `src/config/widget.config.ts`).
   */
  readonly VITE_WIDGET_PROFILE?: string;
  /** Injected from `package.json` version at build time (`vite.config.ts`). */
  readonly VITE_APP_VERSION: string;
}

declare global {
  interface Window {
    /**
     * Optional embed overrides before the widget bundle loads.
     * Applied: **layout / interaction**, and optional **`backend.companyId`** (legacy `tenantId`), **`lockTenant`**, **`hideTenantField`** only.
     * Ignored from here: `backend.apiUrl`, `socketUrl`, timeouts, plus `uiElements`, `colors`, `typography`, `a11y`,
     * `features`, `app`, `zIndex`, `debug` (use `src/config/widget.config.ts`).
     */
    __HEALTHCHAT_WIDGET_CONFIG__?: Partial<WidgetInitConfig>;
  }
}

export {};
