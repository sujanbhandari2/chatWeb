# Add HealthChat to your website

This guide is for **you** if you want a chat button on your own site or app (WordPress, React, plain HTML, etc.). Follow the steps in order. You do **not** need this repository on your machine unless your team builds the widget themselves.

---

## What you need first

Ask your HealthChat administrator (or DevOps) for:

1. **Base URL** where the widget is hosted — for example `https://chat.yourcompany.com`. All links below use that as an example; replace it with yours.
2. **Tenant ID** (if your organization uses one) so users land in the right workspace.
3. Confirmation that these files are available at that URL:
   - `widget.html`
   - `healthchat-widget-loader.js`
   - The **assets** folder (JavaScript and CSS loaded by `widget.html`)

They should give you **HTTPS** links. Your page and the widget should both use HTTPS.

---

## Easiest method: one script (recommended)

The chat opens as a **floating panel**. The iframe must **resize** when the panel opens and closes. The loader script does that for you automatically.

### Step 1 — Copy this onto your site

Paste **once** per site (for example in your main layout, or just before `</body>` on every page that should show chat).

Change:

- `https://chat.yourcompany.com` → your real widget URL  
- `your-tenant-id` → the tenant ID you were given (or remove `tenantId` / `lockTenant` if your admin says you do not need them)

```html
<script
  src="https://chat.yourcompany.com/healthchat-widget-loader.js"
  data-widget-src="https://chat.yourcompany.com/widget.html"
  data-config='{"tenantId":"your-tenant-id","lockTenant":true,"position":"right","panelWidth":400,"panelHeight":560}'
  async
></script>
```

| Part | What it does |
|------|----------------|
| `src` | Loads the **loader** script from your HealthChat server. |
| `data-widget-src` | Tells the loader where **widget.html** lives (same server is typical). |
| `data-config` | Optional settings as JSON (size, corner, tenant, etc.). |

Save and reload your site. You should see the chat launcher (usually bottom‑right).

---

## Bigger config (optional)

If the JSON in `data-config` gets long or your security policy blocks inline JSON, put the JSON in a separate tag and point the loader at it:

```html
<script type="application/json" id="hc-widget-config">
{
  "tenantId": "your-tenant-id",
  "lockTenant": true,
  "hideTenantField": true,
  "position": "right",
  "offsetBottom": 24,
  "offsetSide": 24,
  "launcherSize": 56,
  "launcherAriaLabel": "Open support chat",
  "defaultOpen": false,
  "panelWidth": 400,
  "panelHeight": 560,
  "closeOnEscape": true,
  "closeOnClickOutside": true,
  "zIndex": 2147483000
}
</script>
<script
  src="https://chat.yourcompany.com/healthchat-widget-loader.js"
  data-widget-src="https://chat.yourcompany.com/widget.html"
  data-config-id="hc-widget-config"
  async
></script>
```

`zIndex` only affects how high the chat floats **above your page** (loader uses it). It is not added to the widget URL.

---

## Customize look and behavior

You can add or change keys inside `data-config` (or the JSON block). Common ones:

| Setting | What it does | Example values |
|---------|----------------|-----------------|
| `tenantId` | Your organization’s ID in HealthChat | string from your admin |
| `lockTenant` | Stops users from changing tenant in the UI | `true` / `false` |
| `hideTenantField` | Hides the tenant field | `true` / `false` |
| `position` | Which corner | `right`, `left`, `bottom-right`, `bottom-left` |
| `offsetBottom` | Space from bottom edge (pixels) | number, e.g. `24` |
| `offsetSide` | Space from left or right edge (pixels) | number, e.g. `24` |
| `launcherSize` | Chat button size (pixels) | number, e.g. `56` |
| `launcherIconUrl` | Custom button image | full URL to an image |
| `launcherAriaLabel` | Screen reader label for the button | e.g. `"Open chat"` |
| `defaultOpen` | Open the panel as soon as the page loads | `true` / `false` |
| `panelWidth` | Chat panel width (pixels) | number, e.g. `400` |
| `panelHeight` | Chat panel height (pixels) | number, e.g. `560` |
| `panelMaxWidth` | Maximum panel width (CSS) | e.g. `"min(100vw - 32px, 96vw)"` |
| `panelMaxHeight` | Maximum panel height (CSS) | e.g. `"min(100vh - 32px, 92vh)"` |
| `panelBorderRadius` | Rounded corners (CSS) | e.g. `"16px"` |
| `panelBoxShadow` | Panel shadow (CSS) | CSS shadow string |
| `closeOnEscape` | Close when user presses Escape | `true` / `false` |
| `closeOnClickOutside` | Close when clicking outside the panel | `true` / `false` |

**API address, live connection, and most product settings** are chosen when HealthChat is **built and deployed** for your organization. If something in the chat itself needs to change (server URL, features, branding), ask your administrator — that usually is not done through this embed snippet.

---

## React, Vue, or other JavaScript apps

**Simplest:** add the same `<script …>` to your app’s main HTML file (for example **`public/index.html`** in Create React App or Vite). No extra React code is required.

**If you cannot edit HTML:** your developer can inject the script once when the app loads (for example in a `useEffect` in your root layout). Prefer the HTML approach when possible so the loader always runs the same way.

**Next.js:** your developer can use the app layout or `next/script` to load `healthchat-widget-loader.js` the same way as a normal script tag, with `data-widget-src` and `data-config` set on that script.

---

## Advanced: your own iframe (no loader)

Only use this if your team **cannot** use the loader script. You must **resize the iframe** when the chat tells you to, or users will see a large invisible box over your page after they close chat.

1. Add an iframe pointing at `widget.html` (with your query parameters if your admin provided any).
2. Add `allow="microphone"` on the iframe if voice messages are used.
3. Add a small script that listens for messages and sets the iframe’s width and height, like this:

```html
<iframe
  id="hc-widget"
  src="http://localhost:5173/widget.html?tenantId=954627c6-0cfb-4088-a058-b32d2636d076"
  title="Chat"
  allow="microphone"
  style="position:fixed;border:0;background:transparent;width:120px;height:120px;bottom:20px;right:20px;z-index:2147483000;overflow:hidden;"
></iframe>
<script>
  window.addEventListener('message', function (ev) {
    var iframe = document.getElementById('hc-widget');
    if (!iframe || ev.source !== iframe.contentWindow) return;
    var d = ev.data;
    if (!d || d.source !== 'healthchat-widget' || d.type !== 'resize') return;
    var w = Number(d.width);
    var h = Number(d.height);
    if (!w || !h || w < 32 || h < 32) return;
    iframe.style.width = w + 'px';
    iframe.style.height = h + 'px';
  });
</script>
```

The widget sends `{ source: 'healthchat-widget', type: 'resize', width, height }` when the panel opens, closes, or the browser window is resized.

---

## Something wrong? Check this first

| What you see | What to try |
|--------------|-------------|
| Empty area on the page after closing chat, or clicks “miss” buttons | Use the **loader script**, or copy the **resize listener** above. Do not put the iframe inside a tall box with a fixed height — let the iframe height change. |
| Chat does not appear | Check the URLs in the script. Open `widget.html` directly in a new tab; if it fails, the server or path is wrong. |
| “Blocked” or blank frame | Your site or HealthChat may block embedding. Your IT team may need to allow your site in **Content Security Policy** (`frame-src`) and ensure **framing** is allowed for your domain. |
| Voice does not work | The iframe must include **`allow="microphone"`** (the loader adds this). Users must allow the microphone when the browser asks. |
| Mixed errors in the console | Use **HTTPS** everywhere, not `http` for the widget on an `https` site. |

---

## For your IT / security team

- Prefer **HTTPS** for your site and for the HealthChat host URL.
- When handling resize messages, only trust messages where **`ev.source`** is your chat iframe’s `contentWindow`, and where **`data.source === 'healthchat-widget'`** and **`data.type === 'resize'`** (same checks as the loader).
- If you use a strict **Content Security Policy**, allow the widget origin in **`frame-src`** (and any rules needed for your own scripts).

---

## Optional: configuration web page

Some deployments include a **configurator** page (for example `config.html`) where your team can preview options and copy a ready-made snippet. Ask your administrator whether that is available and where it lives.

---

*If you maintain the HealthChat product source code itself, see the main project **README** for build commands and developer documentation.*
