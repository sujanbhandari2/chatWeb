import { z } from 'zod';

/**
 * Config schema version and release label (trusted profile only — stripped from embed URL/window).
 */
export const appSchema = z.object({
  /** Bump when `WidgetInitConfig` JSON shape changes in a breaking way (migrations). */
  configSchemaVersion: z.number().int().positive().default(1),
  /** Human-readable build id; `mergeConfig` fills from `VITE_APP_VERSION` when omitted. */
  releaseVersion: z.string().optional(),
});

export type WidgetApp = z.infer<typeof appSchema>;

export const defaultWidgetApp: WidgetApp = appSchema.parse({});
