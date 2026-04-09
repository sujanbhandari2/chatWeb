import { z } from 'zod';
import { sanitizeWidgetClassPrefix } from '../../utils/widget-class-prefix.utils';

/**
 * Host CSS namespace (`.{classPrefix}-root`, …). Trusted profile only — not from embed URL/window.
 */
export const stylingSchema = z.object({
  classPrefix: z
    .string()
    .default('vitafy-chat')
    .transform((s) => sanitizeWidgetClassPrefix(s)),
});
