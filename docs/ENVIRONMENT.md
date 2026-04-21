# Environment variables

Variables are read by Vite (`import.meta.env`). Use [`.env.example`](../.env.example) as a template.

## API and socket (chat client)

| Variable | Purpose |
|----------|---------|
| `VITE_API_URL` | REST API base (e.g. `http://localhost:4040/api`). Used when `WidgetInitConfig.backend.apiUrl` is not set by the merged profile. |
| `VITE_SOCKET_URL` | Socket.IO origin. Used when `backend.socketUrl` is unset after merge. |

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
