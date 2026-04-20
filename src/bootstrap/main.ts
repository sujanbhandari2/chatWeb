/**
 * Single entry bootstrap for resolved widget config (see `docs/CHAT_WIDGET.md`).
 * Merge order: `getWidgetProfilePartial()` → stripped `window` → stripped URL (`getWidgetInitConfig`).
 */
import type { WidgetInitConfig } from '../schemas/widget.schemas';
import { interactionSchema } from '../schemas/widget/interaction.schema';
import { applyWidgetRuntimeFromConfig, getWidgetInitConfig } from '../utils/widget-runtime.utils';

export function bootstrapWidgetResolvedConfig(): WidgetInitConfig {
  const widgetConfig = getWidgetInitConfig();
  applyWidgetRuntimeFromConfig(widgetConfig);
  if (import.meta.env.DEV && typeof window !== 'undefined') {
    const q = window.location.search.startsWith('?')
      ? window.location.search.slice(1)
      : window.location.search;
    if (!new URLSearchParams(q).has('defaultOpen')) {
      return {
        ...widgetConfig,
        interactions: interactionSchema.parse({ ...widgetConfig.interactions, defaultOpen: true })
      };
    }
  }
  return widgetConfig;
}
