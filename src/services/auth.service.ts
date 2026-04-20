import { useMutation } from '@tanstack/react-query';
import { loginTenant } from '../api/auth.api';
import { registerOrGetChatUser } from '../api/chat-users.api';
import { useAuthStore } from '../store/useAuthStore';
import { buildAuthUserFromVitafySession } from '../utils/vitafy-chat.utils';
import type { LoginInput } from '../schemas/auth.schemas';

export const authKeys = {
  all: ['auth'] as const
};

export const useLoginMutation = () => {
  const setSession = useAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: async (body: LoginInput) => {
      const tenant = await loginTenant({ email: body.email, password: body.password });
      const chatUser = await registerOrGetChatUser({
        providerId: 'vitafy-tenant',
        providerUserId: tenant.id,
        email: tenant.email,
        name: tenant.name
      });
      return { token: tenant.token, user: buildAuthUserFromVitafySession(tenant, chatUser) };
    },
    onSuccess: (data) => setSession(data.token, data.user)
  });
};
