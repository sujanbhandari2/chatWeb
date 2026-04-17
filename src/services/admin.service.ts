import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createAdminClient,
  createAdminClientApiKey,
  deleteAdminClient,
  getAdminProfile,
  listAdminClientApiKeys,
  loginAdmin,
  revokeAdminClientApiKey
} from '../api/admin.api';
import { toast } from '../common/ui/Toaster';
import { ApiError } from '../lib/api-error';
import { useAdminAuthStore } from '../store/useAdminAuthStore';
import { pickBearerToken } from '../types/admin.types';

export const adminKeys = {
  all: ['admin'] as const,
  profile: () => [...adminKeys.all, 'profile'] as const,
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

export const useCreateAdminClientMutation = () => {
  return useMutation({
    mutationFn: createAdminClient,
    onError: toastApiError
  });
};

export const useDeleteAdminClientMutation = () =>
  useMutation({
    mutationFn: deleteAdminClient,
    onError: toastApiError
  });

export const useAdminClientApiKeysQuery = (userId: string) => {
  const token = useAdminAuthStore((s) => s.token);
  return useQuery({
    queryKey: adminKeys.userKeys(userId),
    queryFn: () => listAdminClientApiKeys(userId),
    enabled: Boolean(token?.trim() && userId)
  });
};

export const useCreateAdminClientApiKeyMutation = (userId: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Parameters<typeof createAdminClientApiKey>[1]) =>
      createAdminClientApiKey(userId, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.userKeys(userId) }),
    onError: toastApiError
  });
};

export const useRevokeAdminClientApiKeyMutation = (userId: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (keyId: string) => revokeAdminClientApiKey(userId, keyId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.userKeys(userId) }),
    onError: toastApiError
  });
};
