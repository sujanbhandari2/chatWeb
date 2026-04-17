# Chat widget — maintainer guide

**Website integration (access key, iframe, `window` config):** [WIDGET_WEBSITE.md](./WIDGET_WEBSITE.md) · **Public page in app:** `/widget-docs`

## What to edit when

| Goal | Where |
|------|--------|
| Feature flags (`imageUpload`, `createGroup`, …) | Trusted profile: [`src/config/widget.config.ts`](../src/config/widget.config.ts) (`devWidgetSandboxPartial`, `configs.*`, or named examples). Schema: [`src/schemas/widget.schemas.ts`](../src/schemas/widget.schemas.ts) (`featuresSchema`). |
| Theme colors / spacing / launcher | Same `widget.config.ts` profiles; presets use `applyThemePreset` / `mergeConfig`. |
| Default API/socket when profile omits `backend` | [`.env`](../.env.example) `VITE_API_URL`, `VITE_SOCKET_URL` (see [ENVIRONMENT.md](./ENVIRONMENT.md)). |
| Embed-only overrides (tenant, panel size, …) | Host URL params or stripped `window` config — see `CLIENT_VENDOR_TOP_KEYS` in [`src/utils/widget-runtime.utils.ts`](../src/utils/widget-runtime.utils.ts). |
| Zod shape / defaults / `mergeConfig` | [`src/schemas/widget.schemas.ts`](../src/schemas/widget.schemas.ts) only. |

**Single “human” file:** [`src/config/widget.config.ts`](../src/config/widget.config.ts) (TOC at top of file).

## How config is resolved

1. **`getWidgetProfilePartial()`** reads `VITE_WIDGET_PROFILE` and returns a partial config (profile or `custom` / `dark` / `brand` / `full` example).
2. **`getWidgetInitConfig()`** (in `widget-runtime.utils.ts`) merges that with sanitized `window` and URL partials, then **`mergeConfig`** validates.
3. **`bootstrapWidgetResolvedConfig()`** ([`src/bootstrap/widget-app-bootstrap.ts`](../src/bootstrap/widget-app-bootstrap.ts)) calls `getWidgetInitConfig()` + **`applyWidgetRuntimeFromConfig`** so axios/socket use `backend` timeouts and URLs from the merged config when set.

Entries: [`src/main.tsx`](../src/main.tsx) (test app) and [`src/main-widget.tsx`](../src/main-widget.tsx) (embed bundle) both use the same bootstrap.

## Local development

- Default **`npm run dev`** uses **`configs.development`**, which spreads **`devWidgetSandboxPartial`** — edit that object to try flags or UI without changing production.
- **`VITE_WIDGET_PROFILE=full`** loads a large demo preset that includes **fake `backend.apiUrl` / `socketUrl`**. Prefer the dev sandbox + `.env` when hitting a real local API.

## Security model (embed)

Untrusted hosts must not enable uploads, branding, or feature flags via query string. Keys stripped from `window`/URL are listed in **`CLIENT_VENDOR_TOP_KEYS`** in `widget-runtime.utils.ts` (includes `features`, `app`, `colors`, `uiElements`, …). From embed `backend`, **`tenantId`**, **`lockTenant`**, **`hideTenantField`**, **`accessKey`**, **`apiKey`**, and **`secretKey`** are kept so the host can supply `X-Tenant-Id` and `X-Api-Key` (`accessKey:secretKey` when both halves are set; see [WIDGET_WEBSITE.md](./WIDGET_WEBSITE.md)).

**Client flags are not authorization** — enforce sensitive actions on the server.

## Adding a feature flag

1. Add a boolean to **`featuresSchema`** in `widget.schemas.ts` (default `true` unless you want opt-in).
2. **`mergeConfig`** already shallow-merges `features`; no extra merge code needed.
3. Gate UI with **`useWidgetFeatures()`** from [`src/hooks/useWidgetInitConfig.ts`](../src/hooks/useWidgetInitConfig.ts) (or `widgetConfig.features` where context is not used, e.g. `useChatRuntime`).
4. Optional: add a checkbox row in [`WidgetConfigView`](../src/pages/config/WidgetConfigView.tsx) (uses `defaultWidgetFeatures` keys).

## Configurator

- Open **`/config.html`** in dev (`npm run dev`).
- **Copy JSON (customer)** omits `backend`, `styling`, `features`, `app` for public embed documentation.
- **Copy full JSON** is the full merged shape for internal/mobile consumers.

## Build and deploy

- Vite builds **`widget.html`** and **`index.html`**; widget assets live under `dist/`.
- Loader reference: [`public/healthchat-widget-loader.js`](../public/healthchat-widget-loader.js).
- Deeper embed notes: [WIDGET_EMBED.md](./WIDGET_EMBED.md).

## Host page CSS variables (optional)

If you need theme variables on `document.documentElement` outside the React widget shell, call **`applyWidgetCssVariables`** from [`src/utils/widget-css-variables.utils.ts`](../src/utils/widget-css-variables.utils.ts) with the resolved `WidgetInitConfig` (the old unused `initializeWidget` helper was removed in favor of this explicit API).
