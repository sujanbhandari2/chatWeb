import { z } from 'zod';

const nameSchema = z.string().min(1).max(120);
const emailSchema = z.string().email();
const companyIdSchema = z.string().min(1, 'Company is required').max(120);

/**
 * Single user bootstrap for chat: `POST /v1/user/users` (no separate login/register APIs).
 */
export const provisionUserSchema = z.object({
  companyId: companyIdSchema,
  name: nameSchema,
  email: emailSchema,
  /** Stable id for the visitor (defaults to a persisted anonymous id in the widget). */
  externalId: z.string().min(1).max(200)
});

export type ProvisionUserInput = z.infer<typeof provisionUserSchema>;

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((issue) => issue.message).join('; ') || 'Invalid input';
}
