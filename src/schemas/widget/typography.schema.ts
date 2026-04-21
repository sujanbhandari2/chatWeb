import { z } from 'zod';

/** Typography for widget UI. */
export const typographySchema = z.object({
  fontFamily: z.string().default('Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
  fontSize: z.object({
    xs: z.number().positive().default(12),
    sm: z.number().positive().default(14),
    base: z.number().positive().default(16),
    lg: z.number().positive().default(18),
    xl: z.number().positive().default(20),
    '2xl': z.number().positive().default(24),
  }),
  fontWeight: z.object({
    light: z.number().default(300),
    normal: z.number().default(400),
    medium: z.number().default(500),
    semibold: z.number().default(600),
    bold: z.number().default(700),
  }),
  lineHeight: z.number().positive().default(1.5),
  letterSpacing: z.number().default(0),
});
