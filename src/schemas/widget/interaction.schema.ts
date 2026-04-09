import { z } from 'zod';

/** Panel open/close and animation behavior. */
export const interactionSchema = z.object({
  closeOnEscape: z.boolean().default(true),
  closeOnClickOutside: z.boolean().default(true),
  defaultOpen: z.boolean().default(false),
  animationEnabled: z.boolean().default(true),
  animationDuration: z.number().nonnegative().default(300),
});
