import { z } from 'zod';

export const adminLoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

export type AdminLoginFormValues = z.infer<typeof adminLoginSchema>;

export const createAdminTenantSchema = z.object({
  name: z.string().min(1).max(200),
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

export type CreateAdminTenantFormValues = z.infer<typeof createAdminTenantSchema>;

export const createAdminApiKeySchema = z.object({
  name: z.string().max(120).optional(),
  scopesText: z.string().optional(),
  expiresAt: z.string().optional()
});

export type CreateAdminApiKeyFormValues = z.infer<typeof createAdminApiKeySchema>;
