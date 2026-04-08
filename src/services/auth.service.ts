import { useMutation } from '@tanstack/react-query';
import { loginUser, registerUser } from '../api/auth.api';
import { useAuthStore } from '../store/useAuthStore';

export const authKeys = {
  all: ['auth'] as const
};

export const useRegisterMutation = () => {
  const setSession = useAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: registerUser,
    onSuccess: (data) => setSession(data.token, data.user)
  });
};

export const useLoginMutation = () => {
  const setSession = useAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: loginUser,
    onSuccess: (data) => setSession(data.token, data.user)
  });
};
