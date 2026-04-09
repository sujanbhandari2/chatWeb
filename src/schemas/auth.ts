import { z } from 'zod';

const nameSchema = z.string().min(1).max(200);
const emailSchema = z.string().email();
const tenantIdSchema = z.string().uuid();

/** POST /api/auth/create — tenant is required */
export const registerSchema = z.object({
  tenantId: tenantIdSchema,
  name: nameSchema,
  email: emailSchema
});

/** POST /api/auth/login — tenant is required */
export const loginSchema = z.object({
  email: emailSchema,
  tenantId: tenantIdSchema
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type CreateInTenantInput = RegisterInput;
export type LoginInput = z.infer<typeof loginSchema>;

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((issue) => issue.message).join('; ') || 'Invalid input';
}
