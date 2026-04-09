/** Default host-facing CSS namespace (build/admin only; paired with stable `vcw-*` in the DOM). */
export const DEFAULT_WIDGET_CLASS_PREFIX = 'vitafy-chat';

const SAFE_PREFIX = /^[a-z][a-z0-9-]{0,62}$/;

/** Invalid embed values fall back to the default prefix. */
export function sanitizeWidgetClassPrefix(raw: string | undefined): string {
  const s = raw?.trim().toLowerCase();
  if (s && SAFE_PREFIX.test(s)) {
    return s;
  }
  return DEFAULT_WIDGET_CLASS_PREFIX;
}
