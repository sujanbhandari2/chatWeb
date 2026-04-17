import { z } from 'zod';

const nameSchema = z.string().min(1).max(120);
const emailSchema = z.string().email();
const companyIdSchema = z.string().min(1, 'Company is required').max(120);

/**
 * Widget bootstrap: company sets `X-Company-Id`; profile is `POST /api/v1/chat/users`.
 */
export const provisionUserSchema = z.object({
  companyId: companyIdSchema,
  name: nameSchema,
  email: emailSchema
});

export type ProvisionUserInput = z.infer<typeof provisionUserSchema>;

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((issue) => issue.message).join('; ') || 'Invalid input';
}
