# Chat widget on your website

The Vitafy chat widget only runs after it receives an **access key** (client API key). That value is sent on every API request as the `X-Api-Key` header (see OpenAPI `apiKey` security). Without it, the UI shows **Unauthorized** and does not offer sign-in.

For backend details (create client, issue keys), use the **Admin** app at `/admin` or your own integration against `/api/v1/admin/…`.

---

## 1. Get an access key

1. Sign in to the admin console: `https://<your-chat-host>/admin/login`.
2. Create a **client**, then open **API keys** for that client and create a key.
3. Copy the secret once and store it in your **server-side** secrets (environment variable, vault, etc.). **Do not** commit it to public GitHub.

---

## 2. Pass the key into the widget

You can use either name in config: **`accessKey`** (recommended for embedders) or **`apiKey`** (alias; same behavior).

Resolution order for the key:

1. Runtime widget config `backend.accessKey` or `backend.apiKey` (merged from your **build profile** in `src/config/widget.config.ts`).
2. Sanitized **`window.__HEALTHCHAT_WIDGET_CONFIG__`** (nested `backend.accessKey` / `backend.apiKey`).
3. URL query **`?accessKey=`** or **`?apiKey=`** (merged into config; convenient for **local dev only** — query strings leak via logs and Referer).
4. Local dev: **`VITE_API_KEY`** in `.env` (never use this for production traffic to a shared repo).

The merged config is applied in `applyWidgetRuntimeFromConfig()` → `setRuntimeApiCredentials()` → axios adds `X-Api-Key`.

---

## 3. Recommended: `window` config (production)

Your page loads the widget bundle (iframe or script host). Before the widget script runs (or via a small inline script), set a **nested** config object so tenant and key are picked up:

```html
<script>
  window.__HEALTHCHAT_WIDGET_CONFIG__ = {
    backend: {
      accessKey: 'YOUR_CLIENT_API_KEY', // from server-rendered template, not hardcoded in static HTML
      tenantId: 'optional-tenant-id'   // if your API expects X-Tenant-Id
    }
  };
</script>
<!-- then load widget.html or your iframe src pointing at the hosted widget -->
```

Keys in `window` are validated with the widget Zod schema; unknown top-level keys may be stripped — use the nested `backend` shape above.

---

## 4. Iframe example

Point an iframe at your hosted widget URL (same origin or CORS-enabled API base). You may pass **layout** query params (`tenantId`, `position`, …) and optionally **`accessKey`** in dev:

```html
<iframe
  title="Chat"
  src="https://chat.example.com/widget.html?tenantId=my-tenant&position=right&accessKey=YOUR_KEY"
  style="position:fixed;bottom:0;right:0;width:420px;height:640px;border:0;z-index:99999"
></iframe>
```

**Security:** Prefer injecting `accessKey` via **server-rendered** `src` or `window` config so it is not fixed in static HTML checked into git.

`buildWidgetIframeSrc()` in `src/utils/widget-runtime.utils.ts` can append `tenantId` and `accessKey` from a `WidgetInitConfig` object when you build the URL in JS.

---

## 5. Optional: `X-Tenant-Id`

If your API uses multi-tenant routing, set `backend.tenantId` or URL `?tenantId=…`. It is sent as `X-Tenant-Id` alongside `X-Api-Key`.

---

## 6. User sign-in inside the widget

After the access key is present, end users **register** or **log in** (chat user by email). That flow uses chat APIs with **Bearer** (after login) and/or **X-Api-Key** from the embed, depending on your backend.

---

## 7. What does *not* use the embed key

- **Admin** routes (`/api/v1/admin/…`) use a **separate admin JWT**, not the client API key. The embed key is not sent on admin requests (see `src/lib/axios.ts`).

---

## 8. Troubleshooting

| Symptom | Check |
|--------|--------|
| **Unauthorized** in widget | `getResolvedApiKey()` is empty — set `accessKey` / `apiKey` / `VITE_API_KEY` (dev). |
| 401 on chat API | Key revoked, wrong environment base URL, or missing `X-Tenant-Id` if required. |
| CORS errors | API must allow your **page origin** and expose required headers. |

Code entry: `src/pages/chat/widget-chat-app.tsx` (gates on `getResolvedApiKey()`), `src/lib/api-credentials.ts`, `src/utils/widget-runtime.utils.ts`.
