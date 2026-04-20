/**
 * Widget configuration resolution (embed / iframe).
 *
 * Maintainer docs: **`docs/CHAT_WIDGET.md`**, environment variables: **`docs/ENVIRONMENT.md`**.
 *
 * **Merge order** (each step overrides the previous): `getWidgetProfilePartial()` from
 * `config/widget.config.ts` → `window.__HEALTHCHAT_WIDGET_CONFIG__` → URL search params
 * (`parseWidgetConfigFromSearchParams`). **Embedders may set on `backend`:** `tenantId`,
 * `lockTenant`, `hideTenantField`, and optional **`tenantJwt`** (Socket.IO `handshake.auth.token`
 * when the UI session token is not a JWT). **API URLs, sockets, timeouts, and other `backend` keys**
 * come only from your built profile. **Branding / typography / a11y /
 * styling (e.g. `classPrefix`), `features`, and `app`** from window/URL are stripped. **Colors** from the URL are ignored in **production**; in **dev**,
 * `?__hc_cfg_preview=1` with `primaryColor`, `secondaryColor`, … (see `buildWidgetIframeSrc` option
 * `configuratorPreview`) merges for the configurator iframe only.
 *
 * Call **`bootstrapWidgetResolvedConfig()`** from `bootstrap/widget-app-bootstrap.ts` at app entry
 * (used by `main.tsx` and `main-widget.tsx`), then pass the result through `App` → `WidgetChatApp`.
 *
 * **Also used by:** `buildWidgetIframeSrc` (config preview / loader), `WidgetConfigView`.
 */
import { z } from 'zod';
import { getWidgetProfilePartial } from '../config/widget.config';
import {
  defaultWidgetInitConfig,
  mergeConfig,
  widgetInitConfigSchema,
  type DeepPartialWidgetConfig,
  type WidgetInitConfig,
} from '../schemas/widget.schemas';
import { applyRuntimeApiOverrides } from './runtime-endpoints.utils';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const partialWidgetSchema = widgetInitConfigSchema.partial();

const LAUNCHER_POSITIONS = new Set(['left', 'right', 'bottom-left', 'bottom-right'] as const);

function devWarn(message: string, detail?: unknown): void {
  if (import.meta.env.DEV) {
    // eslint-disable-next-line no-console
    console.warn(`[HealthChat widget] ${message}`, detail ?? '');
  }
}

function parseBool(raw: string | null): boolean | undefined {
  switch (raw?.toLowerCase()) {
    case '1': case 'true':  case 'yes': return true;
    case '0': case 'false': case 'no':  return false;
    default: return undefined;
  }
}

function parseNum(raw: string | null): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

function isNestedConfig(o: Record<string, unknown>): boolean {
  return [
    'backend',
    'colors',
    'typography',
    'spacing',
    'launcher',
    'interactions',
    'uiElements',
    'a11y',
    'styling',
    'features',
    'app',
  ].some((key) => key in o);
}

// ---------------------------------------------------------------------------
// Legacy flat → nested config
// ---------------------------------------------------------------------------

type Str = string | undefined;
type Num = number | undefined;
type Bool = boolean | undefined;

const str = (v: unknown): Str => (typeof v === 'string' ? v : undefined);
const num = (v: unknown): Num => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const bool = (v: unknown): Bool => (typeof v === 'boolean' ? v : undefined);

export function legacyFlatToPartialConfig(flat: Record<string, unknown>): DeepPartialWidgetConfig {
  const backend = pickDefined({
    tenantId: str(flat.tenantId),
    lockTenant: bool(flat.lockTenant),
    hideTenantField: bool(flat.hideTenantField)
  });

  const position = str(flat.position);
  const launcher = pickDefined({
    ...(position && LAUNCHER_POSITIONS.has(position as never) ? { position } : {}),
    size:       num(flat.launcherSize),
    iconUrl:    str(flat.launcherIconUrl),
    ariaLabel:  str(flat.launcherAriaLabel),
  });

  const spacing = pickDefined({
    offsetBottom:     num(flat.offsetBottom),
    offsetSide:       num(flat.offsetSide),
    launcherSize:     num(flat.launcherSize),
    panelWidth:       num(flat.panelWidth),
    panelHeight:      num(flat.panelHeight),
    panelMaxWidth:    str(flat.panelMaxWidth),
    panelMaxHeight:   str(flat.panelMaxHeight),
    panelBorderRadius:str(flat.panelBorderRadius),
    panelBoxShadow:   str(flat.panelBoxShadow),
  });

  const interactions = pickDefined({
    defaultOpen:        bool(flat.defaultOpen),
    closeOnEscape:      bool(flat.closeOnEscape),
    closeOnClickOutside:bool(flat.closeOnClickOutside),
  });

  const uiElements  = pickDefined({ panelTitle: str(flat.panelTitle) });

  const fontSize   = num(flat.fontSize);
  const fontWeight = num(flat.fontWeight);
  const typography = pickDefined({
    fontFamily:    str(flat.fontFamily),
    lineHeight:    num(flat.lineHeight),
    letterSpacing: num(flat.letterSpacing),
    ...(fontSize   !== undefined ? { fontSize:   { base:   fontSize   } } : {}),
    ...(fontWeight !== undefined ? { fontWeight: { normal: fontWeight } } : {}),
  });

  const textPrimary = str(flat.textPrimaryColor) ?? str(flat.textColor);
  const textBlock = pickDefined({
    primary: textPrimary,
    secondary: str(flat.textSecondaryColor),
    tertiary: str(flat.textTertiaryColor),
    inverse: str(flat.textInverseColor)
  });
  const statusBlock = pickDefined({
    success: str(flat.statusSuccessColor),
    error: str(flat.statusErrorColor),
    warning: str(flat.statusWarningColor),
    info: str(flat.statusInfoColor)
  });
  const colors = pickDefined({
    primary: str(flat.primaryColor),
    secondary: str(flat.secondaryColor),
    accent: str(flat.accentColor),
    background: str(flat.backgroundColor),
    surface: str(flat.surfaceColor),
    border: str(flat.borderColor),
    ...(Object.keys(textBlock).length > 0 ? { text: textBlock } : {}),
    ...(Object.keys(statusBlock).length > 0 ? { status: statusBlock } : {})
  });

  return pickDefined({
    backend,
    launcher,
    spacing,
    interactions,
    uiElements,
    typography,
    colors,
    zIndex: num(flat.zIndex),
    debug:  bool(flat.debug),
  }) as DeepPartialWidgetConfig;
}

// ---------------------------------------------------------------------------
// Deep-merge
// ---------------------------------------------------------------------------

export function mergeWidgetPartials(...partials: DeepPartialWidgetConfig[]): DeepPartialWidgetConfig {
  return partials.reduce<DeepPartialWidgetConfig>((acc, p) => ({
    ...acc,
    ...p,
    backend:     mergeSection(acc.backend,     p.backend),
    colors:      mergeSection(acc.colors,      p.colors,      ['text', 'status']),
    typography:  mergeSection(acc.typography,  p.typography,  ['fontSize', 'fontWeight']),
    spacing:     mergeSection(acc.spacing,     p.spacing),
    launcher:    mergeSection(acc.launcher,    p.launcher,    ['badge']),
    interactions:mergeSection(acc.interactions,p.interactions),
    uiElements:  mergeSection(acc.uiElements,  p.uiElements),
    a11y:        mergeSection(acc.a11y,        p.a11y),
    styling:     mergeSection(acc.styling,     p.styling),
    features:    mergeSection(acc.features,    p.features),
    app:         mergeSection(acc.app,         p.app),
  }), {});
}

// ---------------------------------------------------------------------------
// URL search params → partial config
// ---------------------------------------------------------------------------

export function parseWidgetConfigFromSearchParams(
  search: string | URLSearchParams,
): DeepPartialWidgetConfig {
  const p = typeof search === 'string'
    ? new URLSearchParams(search.startsWith('?') ? search.slice(1) : search)
    : search;

  const get  = (k: string)                  => p.get(k);
  const getOr = (k: string, fallback: string) => p.get(k) ?? p.get(fallback);

  const position = get('position');

  const flat: Record<string, unknown> = pickDefined({
    tenantId:           get('tenantId') ?? get('tenant') ?? undefined,
    lockTenant:         parseBool(get('lockTenant')),
    hideTenantField:    parseBool(get('hideTenantField')),
    position:           position && LAUNCHER_POSITIONS.has(position as never) ? position : undefined,
    offsetBottom:       parseNum(get('offsetBottom')),
    offsetSide:         parseNum(get('offsetSide')),
    launcherSize:       parseNum(get('launcherSize')),
    launcherIconUrl:    get('launcherIconUrl') ?? undefined,
    launcherAriaLabel:  get('launcherAriaLabel') ?? undefined,
    defaultOpen:        parseBool(get('defaultOpen')),
    closeOnEscape:      parseBool(get('closeOnEscape')),
    closeOnClickOutside:parseBool(get('closeOnClickOutside')),
    panelWidth:         parseNum(getOr('panelWidth',  'width')),
    panelHeight:        parseNum(getOr('panelHeight', 'height')),
    panelMaxWidth:      getOr('panelMaxWidth',  'maxWidth')  ?? undefined,
    panelMaxHeight:     getOr('panelMaxHeight', 'maxHeight') ?? undefined,
    panelBorderRadius: get('panelBorderRadius') ?? undefined,
    panelBoxShadow: get('panelBoxShadow') ?? undefined,
    primaryColor: get('primaryColor') ?? undefined,
    secondaryColor: get('secondaryColor') ?? undefined,
    accentColor: get('accentColor') ?? undefined,
    backgroundColor: get('backgroundColor') ?? undefined,
    surfaceColor: get('surfaceColor') ?? undefined,
    borderColor: get('borderColor') ?? undefined,
    textPrimaryColor: get('textPrimaryColor') ?? undefined,
    textSecondaryColor: get('textSecondaryColor') ?? undefined,
    textTertiaryColor: get('textTertiaryColor') ?? undefined,
    textInverseColor: get('textInverseColor') ?? undefined,
    statusSuccessColor: get('statusSuccessColor') ?? undefined,
    statusErrorColor: get('statusErrorColor') ?? undefined,
    statusWarningColor: get('statusWarningColor') ?? undefined,
    statusInfoColor: get('statusInfoColor') ?? undefined,
    textColor: get('textColor') ?? undefined
  });

  return legacyFlatToPartialConfig(flat);
}

// ---------------------------------------------------------------------------
// Config resolution
// ---------------------------------------------------------------------------

function readWindowPartial(): DeepPartialWidgetConfig {
  if (typeof window === 'undefined') return {};
  return stripClientWidgetOverrides(normalizeEmbedObject(window.__HEALTHCHAT_WIDGET_CONFIG__));
}

function normalizeEmbedObject(raw: unknown): DeepPartialWidgetConfig {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const o = raw as Record<string, unknown>;
  if (isNestedConfig(o)) {
    const parsed = partialWidgetSchema.safeParse(o);
    if (!parsed.success) {
      devWarn('Invalid nested widget config', z.treeifyError(parsed.error));
      return {};
    }
    return parsed.data;
  }
  return legacyFlatToPartialConfig(o);
}

export function mergeWidgetConfig(...partials: DeepPartialWidgetConfig[]): WidgetInitConfig {
  try {
    return mergeConfig(mergeWidgetPartials(...partials));
  } catch (err) {
    devWarn('Merged widget config failed validation; using defaults', err);
    return defaultWidgetInitConfig;
  }
}

/** Dev-only: configurator iframe sets this so theme colors in the query string are merged (production builds ignore). */
export const CONFIGURATOR_PREVIEW_QUERY_FLAG = '__hc_cfg_preview';

function isConfiguratorPreviewUrlSearch(search: string): boolean {
  if (!import.meta.env.DEV) {
    return false;
  }
  const q = search.startsWith('?') ? search.slice(1) : search;
  return new URLSearchParams(q).get(CONFIGURATOR_PREVIEW_QUERY_FLAG) === '1';
}

export function getWidgetInitConfig(): WidgetInitConfig {
  if (typeof window === 'undefined') {
    return mergeWidgetConfig(getWidgetProfilePartial());
  }
  const search = window.location.search;
  const rawUrl = parseWidgetConfigFromSearchParams(search);
  const urlPartial = stripClientWidgetOverrides(rawUrl, {
    preserveColors: isConfiguratorPreviewUrlSearch(search)
  });
  return mergeWidgetConfig(getWidgetProfilePartial(), readWindowPartial(), urlPartial);
}

/** Push resolved `backend` URL and timeout into the shared runtime used by axios / sockets. */
export function applyWidgetRuntimeFromConfig(config: WidgetInitConfig): void {
  const b = config.backend;
  applyRuntimeApiOverrides({
    apiUrl: b?.apiUrl,
    socketUrl: b?.socketUrl,
    apiTimeout: b?.apiTimeout
  });
}

// ---------------------------------------------------------------------------
// iFrame src builder
// ---------------------------------------------------------------------------

type Scalar = string | number | boolean;

/** Query keys safe for third-party embeds: tenant routing + layout + interaction (not API/branding). */
const IFRAME_PARAM_MAP: Array<[string, (c: WidgetInitConfig) => Scalar | undefined]> = [
  ['tenantId', (c) => c.backend?.tenantId],
  ['lockTenant', (c) => c.backend?.lockTenant],
  ['hideTenantField', (c) => c.backend?.hideTenantField],
  ['position', (c) => c.launcher?.position],
  ['offsetBottom', (c) => c.spacing?.offsetBottom],
  ['offsetSide', (c) => c.spacing?.offsetSide],
  ['launcherSize', (c) => c.spacing?.launcherSize],
  ['launcherIconUrl', (c) => c.launcher?.iconUrl],
  ['launcherAriaLabel', (c) => c.launcher?.ariaLabel],
  ['defaultOpen', (c) => c.interactions?.defaultOpen],
  ['panelWidth', (c) => c.spacing?.panelWidth],
  ['panelHeight', (c) => c.spacing?.panelHeight],
  ['panelMaxWidth', (c) => c.spacing?.panelMaxWidth],
  ['panelMaxHeight', (c) => c.spacing?.panelMaxHeight],
  ['panelBorderRadius', (c) => c.spacing?.panelBorderRadius],
  ['panelBoxShadow', (c) => c.spacing?.panelBoxShadow],
  ['closeOnEscape', (c) => c.interactions?.closeOnEscape],
  ['closeOnClickOutside', (c) => c.interactions?.closeOnClickOutside]
];

/** Only appended for `configuratorPreview` iframe src (requires dev widget + `__hc_cfg_preview=1`). */
const CONFIGURATOR_COLOR_IFRAME_MAP: Array<[string, (c: WidgetInitConfig) => string | undefined]> = [
  ['primaryColor', (c) => c.colors?.primary],
  ['secondaryColor', (c) => c.colors?.secondary],
  ['accentColor', (c) => c.colors?.accent],
  ['backgroundColor', (c) => c.colors?.background],
  ['surfaceColor', (c) => c.colors?.surface],
  ['borderColor', (c) => c.colors?.border],
  ['textPrimaryColor', (c) => c.colors?.text?.primary],
  ['textSecondaryColor', (c) => c.colors?.text?.secondary],
  ['textTertiaryColor', (c) => c.colors?.text?.tertiary],
  ['textInverseColor', (c) => c.colors?.text?.inverse],
  ['statusSuccessColor', (c) => c.colors?.status?.success],
  ['statusErrorColor', (c) => c.colors?.status?.error],
  ['statusWarningColor', (c) => c.colors?.status?.warning],
  ['statusInfoColor', (c) => c.colors?.status?.info]
];

export type BuildWidgetIframeSrcOptions = {
  /** Append theme color query params + `__hc_cfg_preview=1` so the widget dev server merges colors (see `getWidgetInitConfig`). */
  configuratorPreview?: boolean;
};

export function buildWidgetIframeSrc(
  baseUrl: string,
  config: WidgetInitConfig,
  options?: BuildWidgetIframeSrcOptions,
): string {
  const base = typeof window !== 'undefined' ? window.location.origin : 'http://localhost';
  const url = new URL(baseUrl, base);
  const params = new URLSearchParams(url.search);

  for (const [key, getValue] of IFRAME_PARAM_MAP) {
    const v = getValue(config);
    if (v === undefined || v === '') continue;
    params.set(key, typeof v === 'boolean' ? String(v) : String(v));
  }

  if (options?.configuratorPreview) {
    params.set(CONFIGURATOR_PREVIEW_QUERY_FLAG, '1');
    for (const [key, getValue] of CONFIGURATOR_COLOR_IFRAME_MAP) {
      const v = getValue(config);
      if (v === undefined || v === '') continue;
      params.set(key, v);
    }
  }

  url.search = params.toString();
  return url.toString();
}

// ---------------------------------------------------------------------------
// Private utilities
// ---------------------------------------------------------------------------

/** Shallow-merge two optional section objects, deep-merging listed sub-keys. */
function mergeSection<T extends Record<string, unknown>>(
  a: T | undefined,
  b: T | undefined,
  deepKeys: string[] = [],
): T | undefined {
  if (!a && !b) return undefined;
  const merged = { ...a, ...b } as T;
  for (const key of deepKeys) {
    const av = (a as Record<string, unknown>)?.[key];
    const bv = (b as Record<string, unknown>)?.[key];
    if (av || bv) {
      (merged as Record<string, unknown>)[key] = { ...(av as object), ...(bv as object) };
    }
  }
  return merged;
}

/** Return a copy of `obj` with all `undefined` values removed. */
function pickDefined<T extends Record<string, unknown>>(obj: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined),
  ) as Partial<T>;
}

/** Top-level keys embedders must not set via window/URL (profile / build only). */
const CLIENT_VENDOR_TOP_KEYS = [
  'uiElements',
  'colors',
  'typography',
  'a11y',
  'styling',
  'features',
  'app',
  'zIndex',
  'debug'
] as const satisfies readonly (keyof DeepPartialWidgetConfig)[];

/** From window/URL `backend`, keep tenant-facing fields (+ optional `tenantJwt`); API sockets/timeouts stay profile-only. */
function sanitizeEmbedderBackendPartial(
  backend: unknown
): DeepPartialWidgetConfig['backend'] | undefined {
  if (!backend || typeof backend !== 'object' || Array.isArray(backend)) {
    return undefined;
  }
  const b = backend as Record<string, unknown>;
  const tid = str(b.tenantId);
  const jwtRaw = str(b.tenantJwt);
  const tenantJwt =
    jwtRaw !== undefined && jwtRaw.trim() !== '' ? jwtRaw.trim() : undefined;
  return pickDefined({
    tenantId: tid !== undefined && tid.trim() !== '' ? tid.trim() : undefined,
    lockTenant: bool(b.lockTenant),
    hideTenantField: bool(b.hideTenantField),
    tenantJwt
  }) as DeepPartialWidgetConfig['backend'];
}

function stripClientWidgetOverrides(
  p: DeepPartialWidgetConfig,
  opts?: { preserveColors?: boolean }
): DeepPartialWidgetConfig {
  const o = { ...p } as Record<string, unknown>;
  const keysToRemove = opts?.preserveColors
    ? CLIENT_VENDOR_TOP_KEYS.filter((k) => k !== 'colors')
    : CLIENT_VENDOR_TOP_KEYS;
  for (const key of keysToRemove) {
    delete o[key];
  }
  const safeBackend = sanitizeEmbedderBackendPartial(o.backend);
  if (safeBackend && Object.keys(safeBackend as object).length > 0) {
    o.backend = safeBackend;
  } else {
    delete o.backend;
  }
  return o as DeepPartialWidgetConfig;
}