import { z } from 'zod';

/** Public embed contract — single source of truth with Zod (integrators + runtime). */
export const widgetInitConfigSchema = z.object({
  tenantId: z.string().optional(),
  lockTenant: z.boolean().default(false),
  hideTenantField: z.boolean().default(false),
  position: z.enum(['left', 'right']).default('right'),
  offsetBottom: z.number().nonnegative().default(24),
  offsetSide: z.number().nonnegative().default(24),
  launcherSize: z.number().positive().default(56),
  launcherIconUrl: z.string().optional(),
  launcherAriaLabel: z.string().default('Open chat'),
  defaultOpen: z.boolean().default(false),
  panelWidth: z.number().positive().default(380),
  panelHeight: z.number().positive().default(560),
  panelMaxWidth: z.string().optional(),
  panelMaxHeight: z.string().optional(),
  panelBorderRadius: z.string().default('16px'),
  panelBoxShadow: z
    .string()
    .default('0 12px 40px rgba(15, 23, 42, 0.18)'),
  zIndex: z.number().default(99999),
  closeOnEscape: z.boolean().default(true),
  closeOnClickOutside: z.boolean().default(true),
  apiUrl: z.string().optional(),
  socketUrl: z.string().optional(),
  panelTitle: z.string().optional()
});

export type WidgetInitConfig = z.infer<typeof widgetInitConfigSchema>;

export const defaultWidgetInitConfig: WidgetInitConfig = widgetInitConfigSchema.parse({});
