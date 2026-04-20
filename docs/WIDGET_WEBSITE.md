# Chat widget on your website

**Public implementation guide (same app):** open **`/widget-docs`** on your deployed or local dev server (e.g. `http://localhost:5173/widget-docs`).

The Vitafy chat widget only runs after it receives a valid **tenant API credential** (embed key). Outbound **`X-Api-Key`** is always sent as **`accessKey:`** followed by the merged credential (typically **`publicId:secret`** from key creation, or a single string from **`VITE_WIDGET_ACCESS_KEY`**). You may set `backend.accessKey` / `apiKey` and optional **`backend.secretKey`**; do not add the `accessKey:` prefix in config—it is applied in the HTTP layer (`formatWireXApiKeyValue`). Without a resolved credential, the UI shows **Unauthorized**.

For backend details (create **tenant**, issue keys), use the **Admin** app at **`/admin`** (e.g. **`/admin/tenants`**) or your own integration against **`/api/v1/admin/…`**.

---

## 1. Get an API credential

1. Sign in to the admin console: `https://<your-chat-host>/admin/login`.
2. Create a **tenant**, then open **API keys** for that tenant and create a key.
3. Copy the **`accessKey:secretKey`** value once (admin UI shows the full header string) and store it in **server-side** secrets (environment variable, vault, etc.). **Do not** commit it to public GitHub.

---

## 2. Pass the credential into the widget

Use **`backend.accessKey`** (recommended) or **`backend.apiKey`** for the **public id** (or a full `id:secret` string). Optionally set **`backend.secretKey`** for the secret half; the widget runtime merges these, then axios sends the **`X-Api-Key`** header as the literal prefix **`accessKey:`** plus the merged credential (`formatWireXApiKeyValue`).

Resolution order for the merged credential:

1. Runtime widget config `backend.accessKey` / `apiKey` / `secretKey` (from your **build profile** in `src/config/widget.config.ts`).
2. Sanitized **`window.__HEALTHCHAT_WIDGET_CONFIG__`** (nested `backend` fields above).
3. URL query **`?accessKey=`**, **`?apiKey=`**, **`?secretKey=`** (local dev only — query strings leak via logs and Referer).
4. Local dev: **`VITE_WIDGET_ACCESS_KEY`** and optional **`VITE_WIDGET_SECRET_KEY`** in `.env` (inlined by `widget.html`; never commit real keys).

The merged config is applied in `applyWidgetRuntimeFromConfig()` → `setRuntimeApiCredentials()` → axios sets `X-Api-Key` via `formatWireXApiKeyValue` (`src/utils/chat-api-key.utils.ts`).

---

## 3. Recommended: `window` config (production)

Your page loads the widget bundle (iframe or script host). Before the widget script runs (or via a small inline script), set a **nested** config object with at least the API key material:

```html
<script>
  window.__HEALTHCHAT_WIDGET_CONFIG__ = {
    backend: {
      accessKey: 'YOUR_ACCESS_KEY_ID',
      secretKey: 'YOUR_SECRET' // or one accessKey string 'id:secret' and omit secretKey
    }
  };
</script>
<!-- then load widget.html or your iframe src pointing at the hosted widget -->
```

Optional **`backend.companyId`** / legacy **`tenantId`** may still appear in merged config for **URL or UI** (e.g. iframe query params); they are **not** sent as **`X-Company-Id`** on REST requests from this app.

Keys in `window` are validated with the widget Zod schema; unknown top-level keys may be stripped — use the nested `backend` shape above.

---

## 4. Iframe example

Point an iframe at your hosted widget URL (same origin or CORS-enabled API base). You may pass **layout** query params (`position`, …) and optionally **`accessKey`** in dev:

```html
<iframe
  title="Chat"
  src="https://chat.example.com/widget.html?position=right&accessKey=YOUR_KEY"
  style="position:fixed;bottom:0;right:0;width:420px;height:640px;border:0;z-index:99999"
></iframe>
```

**Security:** Prefer injecting `accessKey` via **server-rendered** `src` or `window` config so it is not fixed in static HTML checked into git.

`buildWidgetIframeSrc()` in `src/utils/widget-runtime.utils.ts` can append layout params and `accessKey` from a `WidgetInitConfig` object when you build the URL in JS.

---

## 5. End users inside the widget

After the embed credential is present, visitors enter **`providerId`**, **`providerUserId`**, **email**, and optional **display name**. The app calls **`POST /api/v1/chat/users`** with **`CreateUserDto`**: **`providerId`**, **`providerUserId`**, **`email`**, and optional **`name`**. The web client does **not** send **`X-Company-Id`**. There is no separate tenant login for visitors. Your backend may still return a **Bearer** token for sockets; chat REST calls work with **`X-Api-Key`** when no JWT is returned.

---

## 6. What does *not* use the embed key

- **Admin** routes (`/api/v1/admin/…`) use a **separate admin JWT**, not the tenant embed key. The embed key is not sent on admin requests (see `src/lib/axios.ts`).

---

## 7. Troubleshooting

| Symptom | Check |
|--------|--------|
| **Unauthorized** in widget | `getResolvedApiKey()` is empty — set `accessKey`+`secretKey`, a combined `accessKey` (`id:secret`), or dev env vars. |
| 401 on chat API | Key revoked or wrong environment base URL. |
| CORS errors | API must allow your **page origin** and expose required headers. |

Code entry: `src/pages/chat/widget-chat-app.tsx` (gates on `getResolvedApiKey()`), `src/lib/api-credentials.ts`, `src/utils/widget-runtime.utils.ts`.

---

## 8. `widget.html` (this repo)

The [`widget.html`](../widget.html) page runs an **inline** `<script type="module">` **before** [`src/main-widget.tsx`](../src/main-widget.tsx). It sets `window.__HEALTHCHAT_WIDGET_CONFIG__.backend` from **`VITE_WIDGET_ACCESS_KEY`**, optional **`VITE_WIDGET_SECRET_KEY`**, and optional **`VITE_WIDGET_COMPANY_ID`** / **`VITE_WIDGET_TENANT_ID`** (for config/URL only — not sent as `X-Company-Id`). Copy [`.env.example`](../.env.example) for local runs. For production, replace the env-based inline script with a **server-rendered** `<script>` so secrets are not in the built HTML.
