import { useQuery } from '@tanstack/react-query';
import { getTenantUsers } from '../api/users.api';
import { useAuthStore } from '../store/useAuthStore';

export const userKeys = {
  all: ['users'] as const,
  tenant: () => [...userKeys.all, 'tenant'] as const
};

export const useTenantUsersQuery = () => {
  const token = useAuthStore((s) => s.token);
  return useQuery({
    queryKey: userKeys.tenant(),
    queryFn: () => getTenantUsers(),
    enabled: !!token,
    refetchInterval: 8000
  });
};
