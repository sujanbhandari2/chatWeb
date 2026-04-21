/**
 * Single entry bootstrap for resolved widget config (see `docs/CHAT_WIDGET.md`).
 * Merge order: `getWidgetProfilePartial()` → stripped `window` → stripped URL (`getWidgetInitConfig`).
 */
import type { WidgetInitConfig } from '../schemas/widget.schemas';
import { applyWidgetRuntimeFromConfig, getWidgetInitConfig } from '../utils/widget-runtime.utils';

export function bootstrapWidgetResolvedConfig(): WidgetInitConfig {
  const widgetConfig = getWidgetInitConfig();
  applyWidgetRuntimeFromConfig(widgetConfig);
  return widgetConfig;
}
