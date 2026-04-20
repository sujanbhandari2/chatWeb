import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createAdminTenant,
  createAdminTenantApiKey,
  deleteAdminTenant,
  getAdminProfile,
  listAdminTenantApiKeys,
  listAdminTenants,
  loginAdmin,
  revokeAdminTenantApiKey,
  updateAdminTenant
} from '../api/admin.api';
import { toast } from '../common/ui/Toaster';
import { ApiError } from '../lib/api-error';
import { useAdminAuthStore } from '../store/useAdminAuthStore';
import { pickBearerToken } from '../types/admin.types';

export const adminKeys = {
  all: ['admin'] as const,
  profile: () => [...adminKeys.all, 'profile'] as const,
  tenants: () => [...adminKeys.all, 'tenants'] as const,
  userKeys: (userId: string) => [...adminKeys.all, 'api-keys', userId] as const
};

function toastApiError(err: unknown): void {
  const msg = err instanceof ApiError ? err.message : err instanceof Error ? err.message : 'Request failed';
  toast(msg);
}

export const useAdminProfileQuery = () => {
  const token = useAdminAuthStore((s) => s.token);
  return useQuery({
    queryKey: adminKeys.profile(),
    queryFn: () => getAdminProfile(),
    enabled: Boolean(token?.trim())
  });
};

export const useAdminTenantsQuery = () => {
  const token = useAdminAuthStore((s) => s.token);
  return useQuery({
    queryKey: adminKeys.tenants(),
    queryFn: () => listAdminTenants(),
    enabled: Boolean(token?.trim())
  });
};

export const useAdminLoginMutation = () => {
  const setSession = useAdminAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: loginAdmin,
    onSuccess: (data) => {
      const t = pickBearerToken(data);
      if (t) {
        setSession(t);
      }
    },
    onError: toastApiError
  });
};

export const useCreateAdminTenantMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createAdminTenant,
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.tenants() }),
    onError: toastApiError
  });
};

export const useUpdateAdminTenantMutation = () =>
  useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof updateAdminTenant>[1] }) =>
      updateAdminTenant(id, body),
    onError: toastApiError
  });

export const useDeleteAdminTenantMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteAdminTenant,
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.tenants() }),
    onError: toastApiError
  });
};

export const useAdminTenantApiKeysQuery = (userId: string) => {
  const token = useAdminAuthStore((s) => s.token);
  return useQuery({
    queryKey: adminKeys.userKeys(userId),
    queryFn: () => listAdminTenantApiKeys(userId),
    enabled: Boolean(token?.trim() && userId)
  });
};

export const useCreateAdminTenantApiKeyMutation = (userId: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Parameters<typeof createAdminTenantApiKey>[1]) =>
      createAdminTenantApiKey(userId, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.userKeys(userId) }),
    onError: toastApiError
  });
};

export const useRevokeAdminTenantApiKeyMutation = (userId: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (keyId: string) => revokeAdminTenantApiKey(userId, keyId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.userKeys(userId) }),
    onError: toastApiError
  });
};
