import { z } from 'zod';

/** Header, footer, and branding chrome. */
export const uiElementsSchema = z.object({
  panelTitle: z.string().optional(),
  showHeader: z.boolean().default(true),
  showFooter: z.boolean().default(true),
  showBranding: z.boolean().default(false),
  brandingText: z.string().optional(),
  headerIconUrl: z.string().optional(),
});
