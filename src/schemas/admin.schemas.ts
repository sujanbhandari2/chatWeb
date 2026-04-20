import { z } from 'zod';

const emailSchema = z.string().email();

export const adminLoginSchema = z.object({
  email: emailSchema,
  password: z.string().min(8, 'Password must be at least 8 characters')
});

export type AdminLoginFormValues = z.infer<typeof adminLoginSchema>;
