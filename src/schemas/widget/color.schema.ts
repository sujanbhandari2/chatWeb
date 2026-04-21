import { z } from 'zod';

/** Color palette for widget theming. */
export const colorPaletteSchema = z.object({
  primary: z.string().default('#2563eb'),
  secondary: z.string().default('#64748b'),
  accent: z.string().default('#f59e0b'),
  background: z.string().default('#ffffff'),
  surface: z.string().default('#f8fafc'),
  border: z.string().default('#e2e8f0'),
  text: z.object({
    primary: z.string().default('#1e293b'),
    secondary: z.string().default('#64748b'),
    tertiary: z.string().default('#94a3b8'),
    inverse: z.string().default('#ffffff'),
  }),
  status: z.object({
    success: z.string().default('#10b981'),
    error: z.string().default('#ef4444'),
    warning: z.string().default('#f59e0b'),
    info: z.string().default('#0ea5e9'),
  }),
});
