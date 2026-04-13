import { useQuery } from '@tanstack/react-query';
import { getTenantUsers } from '../api/users.api';
import { getResolvedApiKey } from '../lib/api-credentials';
import { useAuthStore } from '../store/useAuthStore';

export const userKeys = {
  all: ['users'] as const,
  tenant: () => [...userKeys.all, 'tenant'] as const
};

export const useTenantUsersQuery = () => {
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const canQuery = Boolean(user && (token?.trim() || getResolvedApiKey()));
  return useQuery({
    queryKey: userKeys.tenant(),
    queryFn: () => getTenantUsers(),
    enabled: canQuery,
    refetchInterval: 8000
  });
};
