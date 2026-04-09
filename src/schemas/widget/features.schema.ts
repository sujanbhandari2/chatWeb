import { z } from 'zod';

/**
 * Feature toggles (trusted profile only — stripped from embed URL/window).
 * Defaults preserve backward-compatible “all on” behavior.
 */
export const featuresSchema = z.object({
  imageUpload: z.boolean().default(true),
  audioAttachmentUpload: z.boolean().default(true),
  voiceRecording: z.boolean().default(true),
  createGroup: z.boolean().default(true),
  editGroup: z.boolean().default(true),
  chatListSearch: z.boolean().default(true),
  translateMessages: z.boolean().default(true),
  voiceTranscription: z.boolean().default(true),
  messageReactions: z.boolean().default(true),
  deleteConversation: z.boolean().default(true),
});

export type WidgetFeatures = z.infer<typeof featuresSchema>;

export const defaultWidgetFeatures: WidgetFeatures = featuresSchema.parse({});
