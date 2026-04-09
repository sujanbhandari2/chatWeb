import { z } from 'zod';

/** Layout spacing and panel sizing. */
export const spacingSchema = z.object({
  offsetBottom: z.number().nonnegative().default(24),
  offsetSide: z.number().nonnegative().default(24),
  launcherSize: z.number().positive().default(56),
  panelWidth: z.number().positive().default(380),
  panelHeight: z.number().positive().default(560),
  panelMaxWidth: z.string().optional(),
  panelMaxHeight: z.string().optional(),
  panelBorderRadius: z.string().default('12px'),
  panelBoxShadow: z.string().default('0 12px 40px rgba(15, 23, 42, 0.15)'),
});
