# Environment variables

Variables are read by Vite (`import.meta.env`). Use [`.env.example`](../.env.example) as a template.

## API and socket (widget and chat app)

| Variable | Purpose |
|----------|---------|
| `VITE_API_URL` | REST API base (e.g. `http://localhost:4040/api`). Used when `WidgetInitConfig.backend.apiUrl` is not set by the merged profile. |
| `VITE_SOCKET_URL` | Socket.IO origin. Used when `backend.socketUrl` is unset after merge. |
| `VITE_WIDGET_ACCESS_KEY` | Credential material (public id, or `id:secret`, or a value that already starts with `accessKey:`). Inlined in [`widget.html`](../widget.html) and optional dev fallback in [`api-credentials.ts`](../src/lib/api-credentials.ts). Axios sends **`X-Api-Key`** as `accessKey:` plus this merged value unless it already has that prefix ([`formatWireXApiKeyValue`](../src/utils/chat-api-key.utils.ts)). |
| `VITE_WIDGET_SECRET_KEY` | Optional **secret** half; merged with `VITE_WIDGET_ACCESS_KEY` before the `accessKey:` wire prefix is applied. |

## Widget profile (which preset loads first)

| Variable | Values |
|----------|--------|
| `VITE_WIDGET_PROFILE` | **Profiles:** `development`, `staging`, `production` (match `import.meta.env.MODE` if omitted). **Named examples:** `custom`, `dark`, `brand`, `full`. |

If unset, the active Vite `MODE` selects `configs.development` | `staging` | `production` from [`src/config/widget.config.ts`](../src/config/widget.config.ts).

## Build metadata

| Variable | Purpose |
|----------|---------|
| `VITE_APP_VERSION` | Injected at build time from `package.json` `version` in [`vite.config.ts`](../vite.config.ts). Fills `app.releaseVersion` when the profile omits it. |

## Config merge precedence (widget)

Later steps override earlier ones:

1. **`getWidgetProfilePartial()`** — from `widget.config.ts` (profile or named example).
2. **`window.__HEALTHCHAT_WIDGET_CONFIG__`** — only **tenant** fields on `backend` plus safe layout keys; see stripping in `widget-runtime.utils.ts`.
3. **URL query params** — same restricted set as embed iframe params.

Trusted keys such as `features`, `app`, `colors`, `styling`, etc. are **not** taken from `window`/URL.

See [CHAT_WIDGET.md](./CHAT_WIDGET.md) for the full picture.
