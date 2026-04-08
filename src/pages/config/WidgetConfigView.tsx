import { useMemo, useState } from 'react';
import { buildWidgetIframeSrc } from '../../utils/widget-runtime.utils';
import { defaultWidgetInitConfig, widgetInitConfigSchema, type WidgetInitConfig } from '../../schemas/widget.schemas';
import './configurator.css';

function widgetBaseDefault(): string {
  if (typeof window === 'undefined') {
    return 'http://localhost:5173/widget.html';
  }
  const base = import.meta.env.BASE_URL || '/';
  const normalized = base.endsWith('/') ? base : `${base}/`;
  return `${window.location.origin}${normalized}widget.html`;
}

export function WidgetConfigView(): JSX.Element {
  const [baseUrl, setBaseUrl] = useState(widgetBaseDefault);
  const [cfg, setCfg] = useState<WidgetInitConfig>(() => ({ ...defaultWidgetInitConfig }));
  const [previewNonce, setPreviewNonce] = useState(0);
  const [copied, setCopied] = useState(false);

  const { iframeSrc, error } = useMemo(() => {
    const parsed = widgetInitConfigSchema.safeParse(cfg);
    if (!parsed.success) {
      return { iframeSrc: '', error: parsed.error.message };
    }
    try {
      return { iframeSrc: buildWidgetIframeSrc(baseUrl, parsed.data), error: null };
    } catch {
      return { iframeSrc: '', error: 'Invalid widget base URL.' };
    }
  }, [baseUrl, cfg]);

  const patch = (partial: Partial<WidgetInitConfig>): void => {
    setCfg((c) => ({ ...c, ...partial }));
  };

  const copyUrl = async (): Promise<void> => {
    if (!iframeSrc) {
      return;
    }
    try {
      await navigator.clipboard.writeText(iframeSrc);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="hc-config-page">
      <header className="hc-config-header">
        <h1>HealthChat widget configurator</h1>
        <p>
          This page is the <strong>visual editor</strong> for embed settings. It drives the same{' '}
          <code>WidgetInitConfig</code> as URL query params, <code>window.__HEALTHCHAT_WIDGET_CONFIG__</code>, and{' '}
          <code>widget.config.example.json</code>. Use <strong>Update preview</strong> to reload the iframe after
          changes.
        </p>
      </header>

      <div className="hc-config-layout">
        <div className="hc-config-panel">
          <h2>Embed target</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-base-url">Widget page URL</label>
            <input
              id="hc-base-url"
              type="url"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://your-host/widget.html"
            />
          </div>

          <h2>Tenant</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-tenant">tenantId</label>
            <input
              id="hc-tenant"
              type="text"
              value={cfg.tenantId ?? ''}
              onChange={(e) => patch({ tenantId: e.target.value.trim() || undefined })}
              placeholder="UUID"
            />
          </div>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.lockTenant}
              onChange={(e) => patch({ lockTenant: e.target.checked })}
            />
            lockTenant
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.hideTenantField}
              onChange={(e) => patch({ hideTenantField: e.target.checked })}
            />
            hideTenantField
          </label>

          <h2>Panel & launcher</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-pos">position</label>
            <select
              id="hc-pos"
              value={cfg.position}
              onChange={(e) => patch({ position: e.target.value as 'left' | 'right' })}
            >
              <option value="right">right</option>
              <option value="left">left</option>
            </select>
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-pw">panelWidth (px)</label>
            <input
              id="hc-pw"
              type="number"
              min={280}
              max={720}
              value={cfg.panelWidth}
              onChange={(e) => patch({ panelWidth: Number(e.target.value) || defaultWidgetInitConfig.panelWidth })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-ph">panelHeight (px)</label>
            <input
              id="hc-ph"
              type="number"
              min={400}
              max={900}
              value={cfg.panelHeight}
              onChange={(e) => patch({ panelHeight: Number(e.target.value) || defaultWidgetInitConfig.panelHeight })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-title">panelTitle</label>
            <input
              id="hc-title"
              type="text"
              value={cfg.panelTitle ?? ''}
              onChange={(e) => patch({ panelTitle: e.target.value.trim() || undefined })}
              placeholder="Optional"
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-ob">offsetBottom</label>
            <input
              id="hc-ob"
              type="number"
              min={0}
              value={cfg.offsetBottom}
              onChange={(e) => patch({ offsetBottom: Number(e.target.value) || 0 })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-os">offsetSide</label>
            <input
              id="hc-os"
              type="number"
              min={0}
              value={cfg.offsetSide}
              onChange={(e) => patch({ offsetSide: Number(e.target.value) || 0 })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-ls">launcherSize</label>
            <input
              id="hc-ls"
              type="number"
              min={40}
              max={80}
              value={cfg.launcherSize}
              onChange={(e) => patch({ launcherSize: Number(e.target.value) || defaultWidgetInitConfig.launcherSize })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-aria">launcherAriaLabel</label>
            <input
              id="hc-aria"
              type="text"
              value={cfg.launcherAriaLabel}
              onChange={(e) => patch({ launcherAriaLabel: e.target.value })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-icon">launcherIconUrl</label>
            <input
              id="hc-icon"
              type="url"
              value={cfg.launcherIconUrl ?? ''}
              onChange={(e) => patch({ launcherIconUrl: e.target.value.trim() || undefined })}
              placeholder="https://…"
            />
          </div>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.defaultOpen}
              onChange={(e) => patch({ defaultOpen: e.target.checked })}
            />
            defaultOpen
          </label>

          <h2>API (optional)</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-api">apiUrl</label>
            <input
              id="hc-api"
              type="url"
              value={cfg.apiUrl ?? ''}
              onChange={(e) => patch({ apiUrl: e.target.value.trim() || undefined })}
              placeholder="https://host/api"
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-sock">socketUrl</label>
            <input
              id="hc-sock"
              type="url"
              value={cfg.socketUrl ?? ''}
              onChange={(e) => patch({ socketUrl: e.target.value.trim() || undefined })}
              placeholder="https://host"
            />
          </div>

          <h2>Advanced</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-z">zIndex</label>
            <input
              id="hc-z"
              type="number"
              value={cfg.zIndex}
              onChange={(e) => patch({ zIndex: Number(e.target.value) || defaultWidgetInitConfig.zIndex })}
            />
          </div>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.closeOnEscape}
              onChange={(e) => patch({ closeOnEscape: e.target.checked })}
            />
            closeOnEscape
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.closeOnClickOutside}
              onChange={(e) => patch({ closeOnClickOutside: e.target.checked })}
            />
            closeOnClickOutside
          </label>

          <div className="hc-config-actions">
            <button type="button" className="hc-config-btn-primary" onClick={() => setPreviewNonce((n) => n + 1)}>
              Update preview
            </button>
            <button type="button" className="hc-config-btn-secondary" onClick={copyUrl} disabled={!iframeSrc}>
              {copied ? 'Copied!' : 'Copy embed URL'}
            </button>
            <button
              type="button"
              className="hc-config-btn-secondary"
              onClick={() => setCfg({ ...defaultWidgetInitConfig })}
            >
              Reset to defaults
            </button>
          </div>
          {error && <p className="hc-config-error">{error}</p>}
        </div>

        <div className="hc-config-panel">
          <h2>Generated URL</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-src-out">iframe src (read-only)</label>
            <textarea id="hc-src-out" readOnly value={iframeSrc || '(fix errors above)'} rows={5} />
          </div>
          <h2>Live preview</h2>
          <div className="hc-config-preview-frame-wrap">
            {iframeSrc ? (
              <iframe
                key={previewNonce}
                title="Widget preview"
                src={iframeSrc}
                allow="microphone"
              />
            ) : (
              <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>Fix validation errors to preview.</div>
            )}
          </div>
        </div>
      </div>

      <p className="hc-config-footnote">
        Production embed guide: see <code>docs/WIDGET_EMBED.md</code>. Loader script:{' '}
        <code>public/healthchat-widget-loader.js</code>.
      </p>
    </div>
  );
}
