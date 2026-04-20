import { z } from 'zod';

const nameSchema = z.string().min(1).max(120);
const emailSchema = z.string().email();

/** Kept for compatibility; Vitafy tenants are provisioned by an admin (`api_doc.md`). */
export const registerSchema = z.object({
  tenantId: z.string(),
  name: nameSchema,
  email: emailSchema
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(8, 'Password must be at least 8 characters'),
  /** Widget URL / profile tenant hint — not sent to the login API. */
  tenantId: z.string().optional()
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((issue) => issue.message).join('; ') || 'Invalid input';
}
