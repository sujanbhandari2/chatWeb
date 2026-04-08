import { z } from 'zod';
import {
  defaultWidgetInitConfig,
  widgetInitConfigSchema,
  type WidgetInitConfig
} from '../schemas/widget.schemas';

const partialWidgetSchema = widgetInitConfigSchema.partial();

function devWarn(message: string, detail?: unknown): void {
  if (import.meta.env.DEV) {
    // eslint-disable-next-line no-console
    console.warn(`[HealthChat widget] ${message}`, detail ?? '');
  }
}

function parseBooleanParam(raw: string | null): boolean | undefined {
  if (raw === null || raw === '') {
    return undefined;
  }
  const v = raw.toLowerCase();
  if (v === '1' || v === 'true' || v === 'yes') {
    return true;
  }
  if (v === '0' || v === 'false' || v === 'no') {
    return false;
  }
  return undefined;
}

function parseNumberParam(raw: string | null): number | undefined {
  if (raw === null || raw === '') {
    return undefined;
  }
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

/** Map query keys (camelCase + short aliases) → partial config. */
export function parseWidgetConfigFromSearchParams(search: string | URLSearchParams): Partial<WidgetInitConfig> {
  const params = typeof search === 'string' ? new URLSearchParams(search.startsWith('?') ? search.slice(1) : search) : search;
  const out: Record<string, unknown> = {};

  const tenantId = params.get('tenantId') ?? params.get('tenant');
  if (tenantId) {
    out.tenantId = tenantId;
  }

  const lock = parseBooleanParam(params.get('lockTenant'));
  if (lock !== undefined) {
    out.lockTenant = lock;
  }
  const hide = parseBooleanParam(params.get('hideTenantField'));
  if (hide !== undefined) {
    out.hideTenantField = hide;
  }

  const position = params.get('position');
  if (position === 'left' || position === 'right') {
    out.position = position;
  }

  const offsetBottom = parseNumberParam(params.get('offsetBottom'));
  if (offsetBottom !== undefined) {
    out.offsetBottom = offsetBottom;
  }
  const offsetSide = parseNumberParam(params.get('offsetSide'));
  if (offsetSide !== undefined) {
    out.offsetSide = offsetSide;
  }
  const launcherSize = parseNumberParam(params.get('launcherSize'));
  if (launcherSize !== undefined) {
    out.launcherSize = launcherSize;
  }

  const launcherIconUrl = params.get('launcherIconUrl');
  if (launcherIconUrl) {
    out.launcherIconUrl = launcherIconUrl;
  }
  const launcherAriaLabel = params.get('launcherAriaLabel');
  if (launcherAriaLabel) {
    out.launcherAriaLabel = launcherAriaLabel;
  }
  const defaultOpen = parseBooleanParam(params.get('defaultOpen'));
  if (defaultOpen !== undefined) {
    out.defaultOpen = defaultOpen;
  }

  const panelWidth = parseNumberParam(params.get('panelWidth') ?? params.get('width'));
  if (panelWidth !== undefined) {
    out.panelWidth = panelWidth;
  }
  const panelHeight = parseNumberParam(params.get('panelHeight') ?? params.get('height'));
  if (panelHeight !== undefined) {
    out.panelHeight = panelHeight;
  }
  const panelMaxWidth = params.get('panelMaxWidth') ?? params.get('maxWidth');
  if (panelMaxWidth) {
    out.panelMaxWidth = panelMaxWidth;
  }
  const panelMaxHeight = params.get('panelMaxHeight') ?? params.get('maxHeight');
  if (panelMaxHeight) {
    out.panelMaxHeight = panelMaxHeight;
  }
  const panelBorderRadius = params.get('panelBorderRadius');
  if (panelBorderRadius) {
    out.panelBorderRadius = panelBorderRadius;
  }
  const panelBoxShadow = params.get('panelBoxShadow');
  if (panelBoxShadow) {
    out.panelBoxShadow = panelBoxShadow;
  }
  const zIndex = parseNumberParam(params.get('zIndex'));
  if (zIndex !== undefined) {
    out.zIndex = zIndex;
  }

  const closeOnEscape = parseBooleanParam(params.get('closeOnEscape'));
  if (closeOnEscape !== undefined) {
    out.closeOnEscape = closeOnEscape;
  }
  const closeOnClickOutside = parseBooleanParam(params.get('closeOnClickOutside'));
  if (closeOnClickOutside !== undefined) {
    out.closeOnClickOutside = closeOnClickOutside;
  }

  const apiUrl = params.get('apiUrl');
  if (apiUrl) {
    out.apiUrl = apiUrl;
  }
  const socketUrl = params.get('socketUrl');
  if (socketUrl) {
    out.socketUrl = socketUrl;
  }
  const panelTitle = params.get('panelTitle');
  if (panelTitle) {
    out.panelTitle = panelTitle;
  }

  const parsed = partialWidgetSchema.safeParse(out);
  if (!parsed.success) {
    devWarn('Invalid query params for widget config', z.treeifyError(parsed.error));
    return {};
  }
  return parsed.data;
}

function readWindowPartial(): Partial<WidgetInitConfig> {
  if (typeof window === 'undefined') {
    return {};
  }
  const raw = window.__HEALTHCHAT_WIDGET_CONFIG__;
  if (!raw || typeof raw !== 'object') {
    return {};
  }
  const parsed = partialWidgetSchema.safeParse(raw);
  if (!parsed.success) {
    devWarn('Invalid window.__HEALTHCHAT_WIDGET_CONFIG__', z.treeifyError(parsed.error));
    return {};
  }
  return parsed.data;
}

/** URL overrides window for explicit per-link embeds. */
export function mergeWidgetConfig(
  base: WidgetInitConfig,
  windowPartial: Partial<WidgetInitConfig>,
  urlPartial: Partial<WidgetInitConfig>
): WidgetInitConfig {
  const merged = {
    ...base,
    ...windowPartial,
    ...urlPartial
  };
  const result = widgetInitConfigSchema.safeParse(merged);
  if (!result.success) {
    devWarn('Merged widget config failed validation; using defaults where needed', z.treeifyError(result.error));
    return widgetInitConfigSchema.parse({});
  }
  return result.data;
}

export function getWidgetInitConfig(): WidgetInitConfig {
  const windowPartial = readWindowPartial();
  const urlPartial =
    typeof window !== 'undefined' ? parseWidgetConfigFromSearchParams(window.location.search) : {};
  return mergeWidgetConfig(defaultWidgetInitConfig, windowPartial, urlPartial);
}

const QUERY_KEYS: Array<{ key: keyof WidgetInitConfig; query: string }> = [
  { key: 'tenantId', query: 'tenantId' },
  { key: 'lockTenant', query: 'lockTenant' },
  { key: 'hideTenantField', query: 'hideTenantField' },
  { key: 'position', query: 'position' },
  { key: 'offsetBottom', query: 'offsetBottom' },
  { key: 'offsetSide', query: 'offsetSide' },
  { key: 'launcherSize', query: 'launcherSize' },
  { key: 'launcherIconUrl', query: 'launcherIconUrl' },
  { key: 'launcherAriaLabel', query: 'launcherAriaLabel' },
  { key: 'defaultOpen', query: 'defaultOpen' },
  { key: 'panelWidth', query: 'panelWidth' },
  { key: 'panelHeight', query: 'panelHeight' },
  { key: 'panelMaxWidth', query: 'panelMaxWidth' },
  { key: 'panelMaxHeight', query: 'panelMaxHeight' },
  { key: 'panelBorderRadius', query: 'panelBorderRadius' },
  { key: 'panelBoxShadow', query: 'panelBoxShadow' },
  { key: 'zIndex', query: 'zIndex' },
  { key: 'closeOnEscape', query: 'closeOnEscape' },
  { key: 'closeOnClickOutside', query: 'closeOnClickOutside' },
  { key: 'apiUrl', query: 'apiUrl' },
  { key: 'socketUrl', query: 'socketUrl' },
  { key: 'panelTitle', query: 'panelTitle' }
];

/** Build iframe `src` with encoded query params from a resolved config (for hosts / loader). */
export function buildWidgetIframeSrc(baseUrl: string, config: WidgetInitConfig): string {
  const url = new URL(baseUrl, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
  const params = new URLSearchParams(url.search);
  for (const { key, query } of QUERY_KEYS) {
    const v = config[key];
    if (v === undefined || v === '') {
      continue;
    }
    if (typeof v === 'boolean') {
      params.set(query, v ? 'true' : 'false');
    } else {
      params.set(query, String(v));
    }
  }
  url.search = params.toString();
  return url.toString();
}
