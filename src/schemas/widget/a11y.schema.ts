import { z } from 'zod';

/** Accessibility-related widget options. */
export const a11ySchema = z.object({
  ariaLabel: z.string().default('Chat widget'),
  ariaDescribedBy: z.string().optional(),
  reduceMotion: z.boolean().default(false),
  highContrast: z.boolean().default(false),
});
