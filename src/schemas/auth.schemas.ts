import { z } from 'zod';

/** Identity provider or source system key (`CreateUserDto.providerId`). */
const providerIdSchema = z.string().min(1, 'Provider id is required').max(120);
/** User id from that provider / your system (`CreateUserDto.providerUserId`). */
const providerUserIdSchema = z.string().min(1, 'Provider user id is required').max(256);
const emailSchema = z.string().email();
/** Display name; optional on API (defaults server-side). */
const nameSchema = z.string().max(120).optional();

/**
 * Widget bootstrap: `POST /api/v1/chat/users` (`CreateUserDto`).
 */
export const provisionUserSchema = z.object({
  providerId: providerIdSchema,
  providerUserId: providerUserIdSchema,
  email: emailSchema,
  name: nameSchema
});

export type ProvisionUserInput = z.infer<typeof provisionUserSchema>;

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((issue) => issue.message).join('; ') || 'Invalid input';
}
