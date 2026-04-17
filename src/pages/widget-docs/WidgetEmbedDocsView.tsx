import { Link } from 'react-router-dom';
import { WIDGET_PUBLIC_PATHS } from '../../constants/widget.constants';
import { AdminRoutes } from '../../constants/admin.constants';
import './widget-embed-docs.css';

const ORIGIN =
  typeof window !== 'undefined' ? window.location.origin : 'https://your-chat-host.example';

export default function WidgetEmbedDocsView(): JSX.Element {
  return (
    <div className="widget-embed-docs">
      <header className="widget-embed-docs__header">
        <div className="widget-embed-docs__header-inner">
          <h1>Embed the chat widget on your website</h1>
          <p>
            The widget needs a client API credential (<strong>
              merged <code>id:secret</code>
            </strong>{' '}
            as the <code>X-Api-Key</code> header) on every load. Without it, visitors only see <strong>Unauthorized</strong>. This
            page summarizes how to integrate; repo copy also lives in{' '}
            <code>docs/WIDGET_WEBSITE.md</code>.
          </p>
          <nav className="widget-embed-docs__nav" aria-label="Quick links">
            <Link to="/">Open chat app</Link>
            <Link to={AdminRoutes.LOGIN}>Admin console (issue keys)</Link>
            <a href="#access-key">Access key</a>
            <a href="#window-config">Window config</a>
            <a href="#iframe">Iframe</a>
            <a href="#troubleshooting">Troubleshooting</a>
          </nav>
        </div>
      </header>

      <main className="widget-embed-docs__body">
        <section id="access-key">
          <h2>1. Get an access key</h2>
          <ol>
            <li>
              Open the <Link to={AdminRoutes.LOGIN}>admin console</Link>, sign in, and create a <strong>client</strong>.
            </li>
            <li>
              Open <strong>API keys</strong> for that client and create a key. Copy the secret once and store it{' '}
              <strong>server-side</strong> (env / vault)—never in public static HTML or git.
            </li>
          </ol>
        </section>

        <section id="resolution">
          <h2>2. How the widget receives the key</h2>
          <p>
            Use <code>backend.accessKey</code> (or <code>apiKey</code>) for the public id and optional{' '}
            <code>backend.secretKey</code>, or a single combined <code>accessKey</code> string. Resolution order:
          </p>
          <ul>
            <li>
              Build profile in <code>src/config/widget.config.ts</code> (<code>backend.accessKey</code> /{' '}
              <code>apiKey</code> / <code>secretKey</code>)
            </li>
            <li>
              <code>window.__HEALTHCHAT_WIDGET_CONFIG__.backend</code> before the widget bundle runs (same fields)
            </li>
            <li>
              URL query <code>?accessKey=</code>, <code>?apiKey=</code>, <code>?secretKey=</code> (local dev only)
            </li>
            <li>
              Local only: <code>VITE_WIDGET_ACCESS_KEY</code> and optional <code>VITE_WIDGET_SECRET_KEY</code> in{' '}
              <code>.env</code>
            </li>
          </ul>
        </section>

        <section id="window-config">
          <h2>3. Recommended: window config (production)</h2>
          <p>
            Inject the key from your server when you render the page (template variable), then load the widget iframe or
            script:
          </p>
          <pre className="widget-embed-docs__pre">{`<script>
  window.__HEALTHCHAT_WIDGET_CONFIG__ = {
    backend: {
      accessKey: 'YOUR_ACCESS_KEY_ID',
      secretKey: 'YOUR_SECRET',
      companyId: 'optional-company-for-x-company-id'
    }
  };
</script>`}</pre>
          <p className="widget-embed-docs__note">
            Use the nested <code>backend</code> object above. Unknown top-level keys from untrusted embeds may be
            stripped—see <code>widget-runtime.utils.ts</code>.
          </p>
        </section>

        <section id="iframe">
          <h2>4. Iframe example</h2>
          <p>
            Point <code>src</code> at your hosted widget entry (e.g. <code>widget.html</code> on this origin:{' '}
            <code>{ORIGIN}/widget.html</code>).
          </p>
          <pre className="widget-embed-docs__pre">{`<iframe
  title="Support chat"
  src="${ORIGIN}/widget.html?companyId=my-company&position=right"
  style="position:fixed;bottom:0;right:0;width:400px;height:580px;border:0;z-index:99999"
  allow="clipboard-write"
></iframe>`}</pre>
          <p>
            Prefer passing <code>accessKey</code> via <code>window</code> on the iframe&apos;s document (same pattern as
            section 3) rather than long-lived keys in the URL.
          </p>
        </section>

        <section id="company">
          <h2>5. Optional: X-Company-Id</h2>
          <p>
            If your API expects a company scope, set <code>backend.companyId</code> or add <code>?companyId=</code> to
            the widget URL (legacy <code>?tenantId=</code> is still read). It is sent as <code>X-Company-Id</code>{' '}
            together with <code>X-Api-Key</code>.
          </p>
        </section>

        <section id="users">
          <h2>6. End users inside the widget</h2>
          <p>
            After the embed key is present, visitors enter name and email once. The client calls{' '}
            <code>POST /api/v1/chat/users</code> with <code>email</code> and <code>name</code> (optional on the
            server; the widget still collects a display name). <code>backend.companyId</code> is sent as{' '}
            <code>X-Company-Id</code>, not in the JSON body. There is no separate login/register API. Optional JWTs from
            your server are used when returned.
          </p>
        </section>

        <section id="admin-separate">
          <h2>7. Admin API vs embed key</h2>
          <p>
            <code>/api/v1/admin/…</code> uses an <strong>admin JWT</strong>, not the client embed key. The embed key is
            not attached to admin routes (<code>src/lib/axios.ts</code>).
          </p>
        </section>

        <section id="troubleshooting">
          <h2>8. Troubleshooting</h2>
          <div className="widget-embed-docs__table-wrap">
            <table className="widget-embed-docs__table">
              <thead>
                <tr>
                  <th>Symptom</th>
                  <th>What to check</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <strong>Unauthorized</strong> in the widget
                  </td>
                  <td>
                    No resolved <code>X-Api-Key</code>—set <code>accessKey</code>+<code>secretKey</code>, a combined
                    credential, or dev env vars.
                  </td>
                </tr>
                <tr>
                  <td>401 from API</td>
                  <td>Revoked key, wrong <code>VITE_API_URL</code>, or missing company id if required.</td>
                </tr>
                <tr>
                  <td>CORS errors</td>
                  <td>API must allow your site origin and required headers.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <footer className="widget-embed-docs__footer">
          <p style={{ margin: 0 }}>
            Maintainer reference: <code>docs/WIDGET_WEBSITE.md</code> · Entry:{' '}
            <code>src/pages/chat/widget-chat-app.tsx</code> · Public URL path: <code>{WIDGET_PUBLIC_PATHS.EMBED_DOCS}</code>
          </p>
        </footer>
      </main>
    </div>
  );
}
