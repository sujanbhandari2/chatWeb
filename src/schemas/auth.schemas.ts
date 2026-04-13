import { z } from 'zod';

const nameSchema = z.string().min(1).max(120);
const emailSchema = z.string().email();
const tenantIdSchema = z.string().max(120).optional();

export const registerSchema = z.object({
  tenantId: tenantIdSchema,
  name: nameSchema,
  email: emailSchema,
  username: z.string().max(80).optional()
});

export const loginSchema = z.object({
  tenantId: tenantIdSchema,
  email: emailSchema
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((issue) => issue.message).join('; ') || 'Invalid input';
}
