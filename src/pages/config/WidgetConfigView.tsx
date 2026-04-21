import { useMemo, useState } from 'react';
import { configs, widgetConfigExamples } from '../../config/widget.config';
import { buildWidgetIframeSrc, mergeWidgetPartials } from '../../utils/widget-runtime.utils';
import {
  defaultWidgetApp,
  defaultWidgetFeatures,
  defaultWidgetInitConfig,
  mergeConfig,
  widgetInitConfigSchema,
  type DeepPartialWidgetConfig,
  type WidgetFeatures,
  type WidgetInitConfig
} from '../../schemas/widget.schemas';
import './configurator.css';

function widgetBaseDefault(): string {
  if (typeof window === 'undefined') {
    return 'http://localhost:5173/widget.html';
  }
  const base = import.meta.env.BASE_URL || '/';
  const normalized = base.endsWith('/') ? base : `${base}/`;
  return `${window.location.origin}${normalized}widget.html`;
}

const dc = defaultWidgetInitConfig.colors!;
const dt = defaultWidgetInitConfig.typography!;
const ds = defaultWidgetInitConfig.spacing!;
const dl = defaultWidgetInitConfig.launcher!;
const da = defaultWidgetApp;

const WIDGET_FEATURE_KEYS = Object.keys(defaultWidgetFeatures) as (keyof WidgetFeatures)[];

function ColorHexField({
  label,
  value,
  onChange
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
}): JSX.Element {
  const pickerValue = /^#[0-9A-Fa-f]{6}$/.test(value) ? value : '#000000';
  return (
    <div className="hc-config-field">
      <label>{label}</label>
      <div className="hc-config-color-row">
        <input
          type="color"
          aria-label={`${label} color picker`}
          value={pickerValue}
          onChange={(e) => onChange(e.target.value)}
        />
        <input type="text" value={value} onChange={(e) => onChange(e.target.value)} placeholder="#rrggbb" />
      </div>
    </div>
  );
}

export function WidgetConfigView(): JSX.Element {
  const [baseUrl, setBaseUrl] = useState(widgetBaseDefault);
  const [cfg, setCfg] = useState<WidgetInitConfig>(() => mergeConfig({}));
  const [previewNonce, setPreviewNonce] = useState(0);
  const [copied, setCopied] = useState(false);
  const [copiedJsonKind, setCopiedJsonKind] = useState<null | 'customer' | 'full'>(null);
  const [presetKey, setPresetKey] = useState('');

  const { iframeSrc, error } = useMemo(() => {
    const parsed = widgetInitConfigSchema.safeParse(cfg);
    if (!parsed.success) {
      return { iframeSrc: '', error: parsed.error.message };
    }
    try {
      return {
        iframeSrc: buildWidgetIframeSrc(baseUrl, parsed.data, { configuratorPreview: true }),
        error: null
      };
    } catch {
      return { iframeSrc: '', error: 'Invalid widget base URL.' };
    }
  }, [baseUrl, cfg]);

  const patch = (partial: DeepPartialWidgetConfig): void => {
    setCfg((c) => mergeConfig(mergeWidgetPartials(c, partial)));
  };

  const patchLauncherBadge = (
    partial: Partial<NonNullable<NonNullable<WidgetInitConfig['launcher']>['badge']>>
  ): void => {
    const b = cfg.launcher?.badge;
    patch({
      launcher: {
        badge: {
          enabled: b?.enabled ?? false,
          backgroundColor: b?.backgroundColor ?? '#ef4444',
          textColor: b?.textColor ?? '#ffffff',
          count: b?.count,
          ...partial
        }
      }
    });
  };

  const applyPreset = (key: string): void => {
    if (key === '__defaults__') {
      setCfg(mergeConfig({}));
    } else if (key.startsWith('profile:')) {
      const name = key.slice('profile:'.length) as keyof typeof configs;
      setCfg(structuredClone(configs[name] as WidgetInitConfig));
    } else if (key.startsWith('example:')) {
      const name = key.slice('example:'.length) as keyof typeof widgetConfigExamples;
      setCfg(structuredClone(widgetConfigExamples[name] as WidgetInitConfig));
    }
    setPresetKey('');
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

  /** Omit host-controlled sections from JSON meant for customers / embed docs. */
  const copyUserFacingJson = async (): Promise<void> => {
    const parsed = widgetInitConfigSchema.safeParse(cfg);
    if (!parsed.success) {
      return;
    }
    const out = { ...parsed.data } as Record<string, unknown>;
    delete out.backend;
    delete out.styling;
    delete out.features;
    delete out.app;
    try {
      await navigator.clipboard.writeText(JSON.stringify(out, null, 2));
      setCopiedJsonKind('customer');
      window.setTimeout(() => setCopiedJsonKind(null), 2000);
    } catch {
      setCopiedJsonKind(null);
    }
  };

  /** Full validated config for mobile/native apps (includes backend + styling). */
  const copyFullConfigJson = async (): Promise<void> => {
    const parsed = widgetInitConfigSchema.safeParse(cfg);
    if (!parsed.success) {
      return;
    }
    try {
      await navigator.clipboard.writeText(JSON.stringify(parsed.data, null, 2));
      setCopiedJsonKind('full');
      window.setTimeout(() => setCopiedJsonKind(null), 2000);
    } catch {
      setCopiedJsonKind(null);
    }
  };

  const colors = cfg.colors ?? dc;
  const text = colors.text ?? dc.text!;
  const status = colors.status ?? dc.status!;
  const typo = cfg.typography ?? dt;
  const fs = typo.fontSize ?? dt.fontSize!;

  return (
    <div className="hc-config-page">
      <header className="hc-config-header">
        <h1>HealthChat widget configurator</h1>
        <p>
          Preview uses merged <code>widget.config.ts</code> profile + your edits below.{' '}
          <strong>Copy JSON (customer)</strong> omits <code>backend</code>, <code>styling</code>, <code>features</code>,
          and <code>app</code> for public embed docs.{' '}
          <strong>Copy full JSON</strong> is the complete <code>WidgetInitConfig</code> for mobile/native developers (
          same shape as <code>widget.config.full.example.json</code>). With <code>npm run dev</code>, the live iframe
          receives theme colors (preview flag + color query params); production embeds ignore color query overrides.
        </p>
      </header>

      <div className="hc-config-layout">
        <div className="hc-config-panel">
          <h2>Presets (widget.config.ts)</h2>
          <select
            className="hc-config-preset-select"
            value={presetKey}
            onChange={(e) => {
              const k = e.target.value;
              if (k) {
                applyPreset(k);
              }
            }}
          >
            <option value="">Load preset…</option>
            <option value="__defaults__">Schema defaults</option>
            <optgroup label="Env profiles (configs.*)">
              <option value="profile:development">development</option>
              <option value="profile:staging">staging</option>
              <option value="profile:production">production</option>
            </optgroup>
            <optgroup label="Examples (widgetConfigExamples.*)">
              <option value="example:custom">custom</option>
              <option value="example:dark">dark</option>
              <option value="example:brand">brand</option>
              <option value="example:full">full</option>
            </optgroup>
          </select>

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

          <h2>Colors</h2>
          <p className="hc-config-subhead">Palette</p>
          <ColorHexField
            label="primary"
            value={colors.primary}
            onChange={(v) => patch({ colors: { primary: v } })}
          />
          <ColorHexField
            label="secondary"
            value={colors.secondary}
            onChange={(v) => patch({ colors: { secondary: v } })}
          />
          <ColorHexField label="accent" value={colors.accent} onChange={(v) => patch({ colors: { accent: v } })} />
          <ColorHexField
            label="background"
            value={colors.background}
            onChange={(v) => patch({ colors: { background: v } })}
          />
          <ColorHexField label="surface" value={colors.surface} onChange={(v) => patch({ colors: { surface: v } })} />
          <ColorHexField label="border" value={colors.border} onChange={(v) => patch({ colors: { border: v } })} />
          <p className="hc-config-subhead">Text</p>
          <ColorHexField
            label="text.primary"
            value={text.primary}
            onChange={(v) => patch({ colors: { text: { primary: v } } })}
          />
          <ColorHexField
            label="text.secondary"
            value={text.secondary}
            onChange={(v) => patch({ colors: { text: { secondary: v } } })}
          />
          <ColorHexField
            label="text.tertiary"
            value={text.tertiary}
            onChange={(v) => patch({ colors: { text: { tertiary: v } } })}
          />
          <ColorHexField
            label="text.inverse"
            value={text.inverse}
            onChange={(v) => patch({ colors: { text: { inverse: v } } })}
          />
          <p className="hc-config-subhead">Status</p>
          <ColorHexField
            label="status.success"
            value={status.success}
            onChange={(v) => patch({ colors: { status: { success: v } } })}
          />
          <ColorHexField
            label="status.error"
            value={status.error}
            onChange={(v) => patch({ colors: { status: { error: v } } })}
          />
          <ColorHexField
            label="status.warning"
            value={status.warning}
            onChange={(v) => patch({ colors: { status: { warning: v } } })}
          />
          <ColorHexField
            label="status.info"
            value={status.info}
            onChange={(v) => patch({ colors: { status: { info: v } } })}
          />

          <h2>Typography</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-ff">fontFamily</label>
            <input
              id="hc-ff"
              type="text"
              value={typo.fontFamily}
              onChange={(e) => patch({ typography: { fontFamily: e.target.value } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-fsb">fontSize.base (px)</label>
            <input
              id="hc-fsb"
              type="number"
              min={10}
              max={24}
              value={fs.base}
              onChange={(e) =>
                patch({ typography: { fontSize: { base: Number(e.target.value) || fs.base } } })
              }
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-lh">lineHeight</label>
            <input
              id="hc-lh"
              type="number"
              step={0.05}
              min={1}
              max={2}
              value={typo.lineHeight}
              onChange={(e) => patch({ typography: { lineHeight: Number(e.target.value) || typo.lineHeight } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-ls">letterSpacing</label>
            <input
              id="hc-ls"
              type="number"
              step={0.1}
              value={typo.letterSpacing}
              onChange={(e) => patch({ typography: { letterSpacing: Number(e.target.value) || 0 } })}
            />
          </div>

          <h2>UI &amp; branding</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-title">panelTitle</label>
            <input
              id="hc-title"
              type="text"
              value={cfg.uiElements?.panelTitle ?? ''}
              onChange={(e) => patch({ uiElements: { panelTitle: e.target.value.trim() || undefined } })}
              placeholder="Optional"
            />
          </div>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.uiElements?.showHeader ?? true}
              onChange={(e) => patch({ uiElements: { showHeader: e.target.checked } })}
            />
            showHeader
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.uiElements?.showFooter ?? true}
              onChange={(e) => patch({ uiElements: { showFooter: e.target.checked } })}
            />
            showFooter
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.uiElements?.showBranding ?? false}
              onChange={(e) => patch({ uiElements: { showBranding: e.target.checked } })}
            />
            showBranding
          </label>
          <div className="hc-config-field">
            <label htmlFor="hc-brand-txt">brandingText</label>
            <input
              id="hc-brand-txt"
              type="text"
              value={cfg.uiElements?.brandingText ?? ''}
              onChange={(e) => patch({ uiElements: { brandingText: e.target.value.trim() || undefined } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-hdr-icon">headerIconUrl</label>
            <input
              id="hc-hdr-icon"
              type="url"
              value={cfg.uiElements?.headerIconUrl ?? ''}
              onChange={(e) => patch({ uiElements: { headerIconUrl: e.target.value.trim() || undefined } })}
              placeholder="https://…"
            />
          </div>

          <h2>Panel &amp; launcher</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-pos">position</label>
            <select
              id="hc-pos"
              value={cfg.launcher?.position ?? 'right'}
              onChange={(e) =>
                patch({
                  launcher: {
                    position: e.target.value as NonNullable<WidgetInitConfig['launcher']>['position']
                  }
                })
              }
            >
              <option value="right">right</option>
              <option value="left">left</option>
              <option value="bottom-right">bottom-right</option>
              <option value="bottom-left">bottom-left</option>
            </select>
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-pw">panelWidth (px)</label>
            <input
              id="hc-pw"
              type="number"
              min={280}
              max={720}
              value={cfg.spacing?.panelWidth ?? ds.panelWidth}
              onChange={(e) => patch({ spacing: { panelWidth: Number(e.target.value) || ds.panelWidth } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-ph">panelHeight (px)</label>
            <input
              id="hc-ph"
              type="number"
              min={400}
              max={900}
              value={cfg.spacing?.panelHeight ?? ds.panelHeight}
              onChange={(e) => patch({ spacing: { panelHeight: Number(e.target.value) || ds.panelHeight } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-pmw">panelMaxWidth (CSS)</label>
            <input
              id="hc-pmw"
              type="text"
              value={cfg.spacing?.panelMaxWidth ?? ''}
              onChange={(e) => patch({ spacing: { panelMaxWidth: e.target.value.trim() || undefined } })}
              placeholder="e.g. min(100vw - 32px, 96vw)"
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-pmh">panelMaxHeight (CSS)</label>
            <input
              id="hc-pmh"
              type="text"
              value={cfg.spacing?.panelMaxHeight ?? ''}
              onChange={(e) => patch({ spacing: { panelMaxHeight: e.target.value.trim() || undefined } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-pbr">panelBorderRadius</label>
            <input
              id="hc-pbr"
              type="text"
              value={cfg.spacing?.panelBorderRadius ?? ds.panelBorderRadius}
              onChange={(e) => patch({ spacing: { panelBorderRadius: e.target.value } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-pbs">panelBoxShadow</label>
            <input
              id="hc-pbs"
              type="text"
              value={cfg.spacing?.panelBoxShadow ?? ds.panelBoxShadow}
              onChange={(e) => patch({ spacing: { panelBoxShadow: e.target.value } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-ob">offsetBottom</label>
            <input
              id="hc-ob"
              type="number"
              min={0}
              value={cfg.spacing?.offsetBottom ?? ds.offsetBottom}
              onChange={(e) => patch({ spacing: { offsetBottom: Number(e.target.value) || 0 } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-os">offsetSide</label>
            <input
              id="hc-os"
              type="number"
              min={0}
              value={cfg.spacing?.offsetSide ?? ds.offsetSide}
              onChange={(e) => patch({ spacing: { offsetSide: Number(e.target.value) || 0 } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-ls">launcherSize</label>
            <input
              id="hc-ls"
              type="number"
              min={40}
              max={80}
              value={cfg.spacing?.launcherSize ?? ds.launcherSize}
              onChange={(e) => {
                const n = Number(e.target.value) || ds.launcherSize;
                patch({ spacing: { launcherSize: n }, launcher: { size: n } });
              }}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-aria">launcherAriaLabel</label>
            <input
              id="hc-aria"
              type="text"
              value={cfg.launcher?.ariaLabel ?? dl.ariaLabel}
              onChange={(e) => patch({ launcher: { ariaLabel: e.target.value } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-icon">launcherIconUrl</label>
            <input
              id="hc-icon"
              type="url"
              value={cfg.launcher?.iconUrl ?? ''}
              onChange={(e) => patch({ launcher: { iconUrl: e.target.value.trim() || undefined } })}
              placeholder="https://…"
            />
          </div>
          <p className="hc-config-subhead">Launcher badge</p>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.launcher?.badge?.enabled ?? false}
              onChange={(e) => patchLauncherBadge({ enabled: e.target.checked })}
            />
            badge.enabled
          </label>
          <ColorHexField
            label="badge.backgroundColor"
            value={cfg.launcher?.badge?.backgroundColor ?? '#ef4444'}
            onChange={(v) => patchLauncherBadge({ backgroundColor: v })}
          />
          <ColorHexField
            label="badge.textColor"
            value={cfg.launcher?.badge?.textColor ?? '#ffffff'}
            onChange={(v) => patchLauncherBadge({ textColor: v })}
          />
          <div className="hc-config-field">
            <label htmlFor="hc-badge-count">badge.count</label>
            <input
              id="hc-badge-count"
              type="number"
              min={0}
              value={cfg.launcher?.badge?.count ?? ''}
              onChange={(e) => {
                const raw = e.target.value;
                patchLauncherBadge({
                  count: raw === '' ? undefined : Math.max(0, Number(raw) || 0)
                });
              }}
            />
          </div>

          <h2>Interactions</h2>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.interactions?.defaultOpen ?? false}
              onChange={(e) => patch({ interactions: { defaultOpen: e.target.checked } })}
            />
            defaultOpen
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.interactions?.closeOnEscape ?? true}
              onChange={(e) => patch({ interactions: { closeOnEscape: e.target.checked } })}
            />
            closeOnEscape
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.interactions?.closeOnClickOutside ?? true}
              onChange={(e) => patch({ interactions: { closeOnClickOutside: e.target.checked } })}
            />
            closeOnClickOutside
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.interactions?.animationEnabled ?? true}
              onChange={(e) => patch({ interactions: { animationEnabled: e.target.checked } })}
            />
            animationEnabled
          </label>
          <div className="hc-config-field">
            <label htmlFor="hc-anim-dur">animationDuration (ms)</label>
            <input
              id="hc-anim-dur"
              type="number"
              min={0}
              max={2000}
              value={cfg.interactions?.animationDuration ?? 300}
              onChange={(e) =>
                patch({ interactions: { animationDuration: Number(e.target.value) || 0 } })
              }
            />
          </div>

          <h2>Features</h2>
          <p className="hc-config-note">
            Tenant / build-time toggles only — not settable from embed URL or <code>window.__HEALTHCHAT_WIDGET_CONFIG__</code>.
          </p>
          <div className="hc-config-check-grid">
            {WIDGET_FEATURE_KEYS.map((key) => (
              <label key={key} className="hc-config-check">
                <input
                  type="checkbox"
                  checked={cfg.features?.[key] ?? defaultWidgetFeatures[key]}
                  onChange={(e) => patch({ features: { [key]: e.target.checked } })}
                />
                {key}
              </label>
            ))}
          </div>

          <h2>App / versioning</h2>
          <p className="hc-config-note">
            <code>configSchemaVersion</code> documents breaking JSON shape changes. <code>releaseVersion</code> defaults from
            the app build when omitted in profile JSON.
          </p>
          <div className="hc-config-field">
            <label htmlFor="hc-app-schema">app.configSchemaVersion</label>
            <input
              id="hc-app-schema"
              type="number"
              min={1}
              value={cfg.app?.configSchemaVersion ?? da.configSchemaVersion}
              onChange={(e) =>
                patch({ app: { configSchemaVersion: Math.max(1, Number(e.target.value) || 1) } })
              }
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-app-release">app.releaseVersion (optional override)</label>
            <input
              id="hc-app-release"
              type="text"
              value={cfg.app?.releaseVersion ?? ''}
              placeholder={`default: ${import.meta.env.VITE_APP_VERSION}`}
              onChange={(e) =>
                patch({ app: { releaseVersion: e.target.value.trim() || undefined } })
              }
            />
          </div>

          <h2>Accessibility &amp; global</h2>
          <div className="hc-config-field">
            <label htmlFor="hc-a11y-label">a11y.ariaLabel</label>
            <input
              id="hc-a11y-label"
              type="text"
              value={cfg.a11y?.ariaLabel ?? defaultWidgetInitConfig.a11y!.ariaLabel}
              onChange={(e) => patch({ a11y: { ariaLabel: e.target.value } })}
            />
          </div>
          <div className="hc-config-field">
            <label htmlFor="hc-a11y-desc">a11y.ariaDescribedBy</label>
            <input
              id="hc-a11y-desc"
              type="text"
              value={cfg.a11y?.ariaDescribedBy ?? ''}
              onChange={(e) => patch({ a11y: { ariaDescribedBy: e.target.value.trim() || undefined } })}
            />
          </div>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.a11y?.reduceMotion ?? false}
              onChange={(e) => patch({ a11y: { reduceMotion: e.target.checked } })}
            />
            reduceMotion
          </label>
          <label className="hc-config-check">
            <input
              type="checkbox"
              checked={cfg.a11y?.highContrast ?? false}
              onChange={(e) => patch({ a11y: { highContrast: e.target.checked } })}
            />
            highContrast
          </label>
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
              checked={cfg.debug ?? false}
              onChange={(e) => patch({ debug: e.target.checked })}
            />
            debug
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
              onClick={copyUserFacingJson}
              disabled={Boolean(error)}
            >
              {copiedJsonKind === 'customer' ? 'Copied!' : 'Copy JSON (customer)'}
            </button>
            <button
              type="button"
              className="hc-config-btn-secondary"
              onClick={copyFullConfigJson}
              disabled={Boolean(error)}
            >
              {copiedJsonKind === 'full' ? 'Copied!' : 'Copy full JSON (mobile)'}
            </button>
            <button type="button" className="hc-config-btn-secondary" onClick={() => setCfg(mergeConfig({}))}>
              Reset to defaults
            </button>
          </div>
          {error && <p className="hc-config-error">{error}</p>}
        </div>

        <div className="hc-config-panel">
          <h2>Generated URL</h2>
          <p className="hc-config-note">
            In <strong>development</strong>, the preview URL includes <code>__hc_cfg_preview=1</code> and color params so
            the iframe matches your palette. Run both <code>config.html</code> and <code>widget.html</code> from{' '}
            <code>npm run dev</code>. Production embeds do not apply colors from the URL.
          </p>
          <div className="hc-config-field">
            <label htmlFor="hc-src-out">iframe src (read-only)</label>
            <textarea id="hc-src-out" readOnly value={iframeSrc || '(fix errors above)'} rows={5} />
          </div>
          <h2>Live preview</h2>
          <div className="hc-config-preview-frame-wrap">
            {iframeSrc ? (
              <iframe key={previewNonce} title="Widget preview" src={iframeSrc} allow="microphone" />
            ) : (
              <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
                Fix validation errors to preview.
              </div>
            )}
          </div>
        </div>
      </div>

      <p className="hc-config-footnote">
        Open this page at <code>/config.html</code>. Customer JSON sample: <code>widget.config.example.json</code>. Full
        schema sample (mobile/native): <code>widget.config.full.example.json</code>. Loader:{' '}
        <code>public/healthchat-widget-loader.js</code>.
      </p>
    </div>
  );
}
