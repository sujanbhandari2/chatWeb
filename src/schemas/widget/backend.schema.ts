import { z } from 'zod';

/** Company routing and API/socket endpoints (trusted profile). */
export const backendSchema = z.object({
  companyId: z.string().optional(),
  /** Server-issued key for embeds (keep in build profile / trusted host config, not public URLs). */
  apiKey: z.string().optional(),
  /** Same as `apiKey` — preferred name for website embedders (`window` / query). */
  accessKey: z.string().optional(),
  /** Secret half of the credential; with `accessKey` / `apiKey` forms `X-Api-Key: accessKey:secretKey`. */
  secretKey: z.string().optional(),
  lockTenant: z.boolean().default(false),
  hideTenantField: z.boolean().default(false),
  apiUrl: z.string().optional(),
  socketUrl: z.string().optional(),
  apiTimeout: z.number().positive().default(30000),
  retryAttempts: z.number().nonnegative().default(3),
});
