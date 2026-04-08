# HealthChat embeddable widget

The widget is a **separate build entry** (`widget.html`) that runs the same chat UI inside a **floating launcher + panel**. Configure it via **URL query parameters**, **`window.__HEALTHCHAT_WIDGET_CONFIG__`**, or the **optional loader script** in [`public/healthchat-widget-loader.js`](../public/healthchat-widget-loader.js).

**Version:** see `package.json` → `version`. Cache-bust static assets after upgrades, e.g. `https://cdn.example.com/widget.html?v=1.0.0`.

## Widget chat layout (inbox → conversation)

In **widget mode** only, the panel uses a **mobile-style** flow: the **chat list** (conversations first, then “Start a chat”) fills the panel. Tapping a conversation opens the **thread** full width; **←** in the header returns to the list. The full-page app (`index.html`) keeps the side-by-side desktop layout.

Conversation UI inside the widget is styled with **`.chat-stage--widget`** so composer, message width, media, and modals stay usable in a **narrow iframe** (they do not depend on the outer browser viewport width).

## Configurator page (where to edit embed settings)

Use the built-in **config UI** (not a separate product URL—served from this repo’s static build):

| Environment | Open |
|-------------|------|
| Dev | `http://localhost:5173/config.html` |
| Production | `https://YOUR_HOST/config.html` (deploy `dist/config.html` + assets next to `widget.html`) |

That page lets you change every **`WidgetInitConfig`** field, **copy the generated iframe URL**, and **preview** the widget in an iframe. The same values can be set manually via [Quickstart (iframe)](#quickstart-iframe), `window.__HEALTHCHAT_WIDGET_CONFIG__`, or [`widget.config.example.json`](../widget.config.example.json).

## Quickstart (iframe)

Point an iframe at your deployed `widget.html` and pass at least `tenantId` (and usually `lockTenant=true` in production):

```html
<iframe
  title="HealthChat"
  src="https://YOUR_CDN/widget.html?tenantId=YOUR_TENANT_UUID&lockTenant=true&position=right"
  style="position:fixed;bottom:24px;right:24px;width:420px;height:680px;border:0;z-index:99999;background:transparent;"
  allow="microphone"
></iframe>
```

Size the iframe large enough for the **launcher + panel** (see [Loader sizing](#loader-script) for a reference formula). The widget draws fixed UI inside the iframe viewport.

## Quickstart (loader script)

Host `widget.html`, `healthchat-widget-loader.js`, and built assets from the same `dist/` (or CDN). On your site:

```html
<script
  src="https://YOUR_CDN/healthchat-widget-loader.js"
  data-widget-src="https://YOUR_CDN/widget.html"
  data-config='{"tenantId":"YOUR_TENANT_UUID","lockTenant":true,"panelWidth":380,"panelHeight":560,"position":"right"}'
  async
></script>
```

Alternatively, use a JSON block:

```html
<script type="application/json" id="hc-widget-cfg">
  { "tenantId": "YOUR_TENANT_UUID", "lockTenant": true }
</script>
<script
  src="https://YOUR_CDN/healthchat-widget-loader.js"
  data-widget-src="https://YOUR_CDN/widget.html"
  data-config-id="hc-widget-cfg"
  async
></script>
```

### Loader sizing

The loader positions a fixed iframe sized from `panelWidth`, `panelHeight`, `launcherSize`, `offsetBottom`, `offsetSide`, and `zIndex` so the in-frame launcher and panel fit. Adjust those keys if the iframe clips the UI.

## `window.__HEALTHCHAT_WIDGET_CONFIG__`

For same-origin deployments you can set config **before** the widget module executes (e.g. inline script above the widget bundle):

```html
<script>
  window.__HEALTHCHAT_WIDGET_CONFIG__ = {
    tenantId: 'YOUR_TENANT_UUID',
    lockTenant: true,
    panelTitle: 'Support',
    apiUrl: 'https://api.example.com/api',
    socketUrl: 'https://api.example.com'
  };
</script>
```

**Merge order:** `window.__HEALTHCHAT_WIDGET_CONFIG__` is merged first, then **URL query params override** (useful for per-link overrides).

## API reference: `WidgetInitConfig`

Types and defaults live in [`src/widget/types.ts`](../src/widget/types.ts). Runtime parsing uses Zod; invalid keys are ignored with **dev-only** console warnings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tenantId` | string | — | Tenant UUID for register/login. **Set per customer / per embed.** |
| `lockTenant` | boolean | `false` | Makes tenant field read-only when visible. |
| `hideTenantField` | boolean | `false` | Hides tenant field; implies locked. Requires `tenantId`. |
| `position` | `"left"` \| `"right"` | `"right"` | Launcher side. |
| `offsetBottom` | number (px) | `24` | Launcher offset from bottom. |
| `offsetSide` | number (px) | `24` | Launcher offset from left or right. |
| `launcherSize` | number (px) | `56` | Launcher button width/height. |
| `launcherIconUrl` | string | — | Optional image URL inside launcher. |
| `launcherAriaLabel` | string | `"Open chat"` | Accessible name for launcher. |
| `defaultOpen` | boolean | `false` | Open panel on load. |
| `panelWidth` | number (px) | `380` | Panel width. |
| `panelHeight` | number (px) | `560` | Panel height. |
| `panelMaxWidth` | string | responsive | CSS `max-width` (e.g. `min(100vw - 32px, 96vw)`). |
| `panelMaxHeight` | string | responsive | CSS `max-height`. |
| `panelBorderRadius` | string | `16px` | Panel corner radius. |
| `panelBoxShadow` | string | (see code) | Panel shadow. |
| `zIndex` | number | `99999` | Stacking order for launcher + panel. |
| `closeOnEscape` | boolean | `true` | Close panel on Escape. |
| `closeOnClickOutside` | boolean | `true` | Close when clicking outside panel. |
| `apiUrl` | string | env | Overrides `VITE_API_URL` (include `/api` suffix or origin; same rules as env). |
| `socketUrl` | string | env | Overrides `VITE_SOCKET_URL`. |
| `panelTitle` | string | — | Optional title in panel header. |

### URL query aliases

`width` / `height` map to `panelWidth` / `panelHeight`. `tenant` maps to `tenantId`. Booleans accept `true` / `false` / `1` / `0`.

### Building a URL in TypeScript

Use [`buildWidgetIframeSrc`](../src/widget/runtimeConfig.ts) from the app source when you generate links programmatically (same encoding as the loader).

## Security

- **`tenantId` in the URL is visible** (view source, DevTools). That is normal for client-side routing; **do not** put secrets in the widget URL.
- **Authorization** is enforced by your **API and WebSocket** (JWT, tenant checks). The widget only selects which tenant the user authenticates against.
- Prefer **short-lived tokens** issued by your server for future SSO-style flows (not implemented in v1).

## CORS and Socket.IO

- The browser origin that serves **`widget.html`** must be allowed by your API **CORS** policy for `fetch` to `apiUrl`.
- Socket.IO needs the gateway to allow the widget origin (and WebSocket upgrades). Configure your chat server accordingly.

## Sessions, cookies, and third-party contexts

If the **parent site** and **widget origin** differ (e.g. `app.com` embedding `chatcdn.io`), browsers may **partition or block** third-party cookies/storage. Safer patterns:

- Host the widget on a **subdomain** of your app (`chat.app.com` embedding `app.com`), or
- Same-origin iframe from your own static host.

## Content Security Policy (CSP)

Allow at minimum:

- `frame-src` (parent page): origins hosting `widget.html`.
- Widget page: `script-src` for your asset hosts; `connect-src` for `apiUrl` and `socketUrl` (HTTP + `wss:`).

## Troubleshooting

| Issue | Check |
|-------|--------|
| “Missing tenant configuration” | Pass `tenantId` via query, `window` config, or loader JSON. |
| API errors / CORS | `apiUrl` matches server; CORS allows widget origin. |
| Realtime offline | `socketUrl` correct; gateway CORS/WebSocket; firewall. |
| Clipped UI | Increase iframe size or `panelWidth` / `panelHeight` / loader dimensions. |
| Wrong tenant after login | `lockTenant` / `hideTenantField` and `tenantId` on embed; server validates JWT tenant. |

## Example JSON

See [`widget.config.example.json`](../widget.config.example.json) for a full commented template.

## Manual test matrix

1. Build: `npm run build` → `dist/widget.html` exists.
2. `npm run preview` → open `/widget.html?tenantId=test&lockTenant=true` → launcher opens panel; auth shows locked/hidden tenant as configured.
3. Override `apiUrl` / `socketUrl` via query → network tab shows requests to overridden host.
4. Full app `index.html` unchanged: no launcher, full-width messenger after login.
