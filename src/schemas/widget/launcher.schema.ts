import { z } from 'zod';

/** Floating launcher button. */
export const launcherSchema = z.object({
  size: z.number().positive().default(56),
  iconUrl: z.string().optional(),
  ariaLabel: z.string().default('Open chat'),
  position: z.enum(['left', 'right', 'bottom-left', 'bottom-right']).default('right'),
  badge: z
    .object({
      enabled: z.boolean().default(false),
      backgroundColor: z.string().default('#ef4444'),
      textColor: z.string().default('#ffffff'),
      count: z.number().nonnegative().optional(),
    })
    .optional(),
});
