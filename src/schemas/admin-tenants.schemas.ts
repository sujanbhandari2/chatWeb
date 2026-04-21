import { z } from 'zod';

export const adminCreateTenantSchema = z.object({
  name: z.string().min(1).max(200),
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

export type AdminCreateTenantFormValues = z.infer<typeof adminCreateTenantSchema>;

/** Pre-filled from tenant; password may be empty for “no change”. Submit handler sends only deltas. */
export const adminUpdateTenantSchema = z.object({
  name: z.string().max(200),
  email: z.string().email(),
  password: z.union([z.string().min(8, 'Password must be at least 8 characters'), z.literal('')])
});

export type AdminUpdateTenantFormValues = z.infer<typeof adminUpdateTenantSchema>;

export const adminCreateApiKeySchema = z.object({
  name: z.string().max(120).optional(),
  expiresAt: z.string().optional()
});

export type AdminCreateApiKeyFormValues = z.infer<typeof adminCreateApiKeySchema>;
