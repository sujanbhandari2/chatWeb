import { z } from 'zod';

const nameSchema = z.string().min(1).max(120);
const emailSchema = z.string().email();

export const registerSchema = z.object({
  tenantId: z.string(),
  name: nameSchema,
  email: emailSchema
});

export const loginSchema = z.object({
  tenantId: z.string().uuid(),
  email: emailSchema
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((issue) => issue.message).join('; ') || 'Invalid input';
}
