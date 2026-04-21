import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createAdminTenant,
  createTenantApiKey,
  deleteAdminTenant,
  getAdminProfile,
  listAdminTenants,
  listTenantApiKeys,
  loginAdmin,
  revokeTenantApiKey,
  updateAdminTenant
} from '../api/admin.api';
import { toast } from '../common/ui/Toaster';
import { useAdminAuthStore } from '../store/useAdminAuthStore';

export const adminKeys = {
  all: ['admin'] as const,
  profile: () => [...adminKeys.all, 'profile'] as const,
  tenants: () => [...adminKeys.all, 'tenants'] as const,
  tenantApiKeys: (tenantId: string) => [...adminKeys.all, 'api-keys', tenantId] as const
};

export const useAdminLoginMutation = () => {
  const setSession = useAdminAuthStore((s) => s.setSession);
  const qc = useQueryClient();
  return useMutation({
    mutationFn: loginAdmin,
    onSuccess: (data) => {
      setSession(data.token, { id: data.id, email: data.email, name: data.name });
      void qc.invalidateQueries({ queryKey: adminKeys.profile() });
    }
  });
};

export const useAdminProfileQuery = () => {
  const token = useAdminAuthStore((s) => s.token);
  return useQuery({
    queryKey: adminKeys.profile(),
    queryFn: getAdminProfile,
    enabled: !!token
  });
};

export const useAdminTenantsQuery = () => {
  const token = useAdminAuthStore((s) => s.token);
  return useQuery({
    queryKey: adminKeys.tenants(),
    queryFn: listAdminTenants,
    enabled: !!token
  });
};

export const useTenantApiKeysQuery = (tenantId: string | null) => {
  const token = useAdminAuthStore((s) => s.token);
  return useQuery({
    queryKey: adminKeys.tenantApiKeys(tenantId ?? ''),
    queryFn: () => listTenantApiKeys(tenantId!),
    enabled: !!token && !!tenantId
  });
};

export const useCreateTenantMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createAdminTenant,
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.tenants() })
  });
};

export const useUpdateTenantMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: { name?: string; email?: string; password?: string } }) =>
      updateAdminTenant(id, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.tenants() })
  });
};

export const useDeleteTenantMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteAdminTenant(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.tenants() }),
    onError: (e) => toast(e instanceof Error ? e.message : 'Request failed')
  });
};

export const useCreateApiKeyMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      tenantId,
      body
    }: {
      tenantId: string;
      body?: { name?: string; scopes?: string[]; expiresAt?: string };
    }) => createTenantApiKey(tenantId, body),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: adminKeys.tenantApiKeys(vars.tenantId) });
    }
  });
};

export const useRevokeApiKeyMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ tenantId, keyId }: { tenantId: string; keyId: string }) =>
      revokeTenantApiKey(tenantId, keyId),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: adminKeys.tenantApiKeys(vars.tenantId) });
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Request failed')
  });
};
