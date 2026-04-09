import { z } from 'zod';

/** Tenant routing and API/socket endpoints (trusted profile). */
export const backendSchema = z.object({
  tenantId: z.string().optional(),
  lockTenant: z.boolean().default(false),
  hideTenantField: z.boolean().default(false),
  apiUrl: z.string().optional(),
  socketUrl: z.string().optional(),
  apiTimeout: z.number().positive().default(30000),
  retryAttempts: z.number().nonnegative().default(3),
});
