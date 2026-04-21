import { z } from 'zod';

/**
 * Feature toggles (trusted profile only — stripped from embed URL/window).
 * Defaults follow Vitafy `api_doc.md` (no conversation delete, no message delete, group edit is add-members only).
 */
export const featuresSchema = z.object({
  imageUpload: z.boolean().default(true),
  audioAttachmentUpload: z.boolean().default(true),
  voiceRecording: z.boolean().default(true),
  createGroup: z.boolean().default(true),
  /** Add members to an existing group (`POST …/participants`); rename/remove/leave are not in the API. */
  editGroup: z.boolean().default(false),
  chatListSearch: z.boolean().default(true),
  translateMessages: z.boolean().default(false),
  voiceTranscription: z.boolean().default(false),
  messageReactions: z.boolean().default(true),
  deleteConversation: z.boolean().default(false),
  /** Server has no delete-message route; `react_message` / receipts are supported. */
  deleteMessage: z.boolean().default(false),
});

export type WidgetFeatures = z.infer<typeof featuresSchema>;

export const defaultWidgetFeatures: WidgetFeatures = featuresSchema.parse({});
