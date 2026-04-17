import { useMutation } from '@tanstack/react-query';
import { provisionUser } from '../api/auth.api';
import { useAuthStore } from '../store/useAuthStore';

export const authKeys = {
  all: ['auth'] as const
};

export const useProvisionUserMutation = () => {
  const setSession = useAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: provisionUser,
    onSuccess: (data) => setSession(data.token, data.user)
  });
};
