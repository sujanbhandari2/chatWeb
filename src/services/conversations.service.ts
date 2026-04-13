import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as chatApi from '../api/chat.api';
import { getResolvedApiKey } from '../lib/api-credentials';
import { useAuthStore } from '../store/useAuthStore';
import { normalizeMessage } from '../utils/chat.utils';

export const conversationKeys = {
  all: ['conversations'] as const,
  list: () => [...conversationKeys.all, 'list'] as const,
  messages: (conversationId: string) => [...conversationKeys.all, 'messages', conversationId] as const
};

export const useConversationsQuery = () => {
  const token = useAuthStore((s) => s.token);
  const userId = useAuthStore((s) => s.user?.id);
  const canQuery = Boolean(userId && (token?.trim() || getResolvedApiKey()));
  return useQuery({
    queryKey: conversationKeys.list(),
    queryFn: () => chatApi.listConversations(userId!),
    enabled: canQuery
  });
};

export const useMessagesQuery = (conversationId: string) => {
  const token = useAuthStore((s) => s.token);
  const canQuery = Boolean(conversationId && (token?.trim() || getResolvedApiKey()));
  return useQuery({
    queryKey: conversationKeys.messages(conversationId),
    queryFn: () =>
      chatApi.getMessagesPage(conversationId).then((p) => p.data.map(normalizeMessage)),
    enabled: canQuery
  });
};

export const useInvalidateConversations = () => {
  const qc = useQueryClient();
  return () => void qc.invalidateQueries({ queryKey: conversationKeys.list() });
};

export const usePrefetchMessages = () => {
  const qc = useQueryClient();
  const token = useAuthStore((s) => s.token);
  return (conversationId: string) => {
    if (!conversationId || (!token?.trim() && !getResolvedApiKey())) {
      return;
    }
    void qc.prefetchQuery({
      queryKey: conversationKeys.messages(conversationId),
      queryFn: () =>
        chatApi.getMessagesPage(conversationId).then((p) => p.data.map(normalizeMessage))
    });
  };
};

export const useCreateDirectConversationMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => {
      const selfId = useAuthStore.getState().user?.id;
      if (!selfId) {
        throw new Error('Not signed in');
      }
      return chatApi.createDirectConversation(userId, selfId);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useCreateGroupConversationMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ title, participantIds }: { title: string; participantIds: string[] }) =>
      chatApi.createGroupConversation(title, participantIds),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useDeleteConversationMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (conversationId: string) => chatApi.deleteConversationById(conversationId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useUpdateConversationMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ conversationId, title }: { conversationId: string; title: string }) =>
      chatApi.updateConversationById(conversationId, { title }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useAddParticipantsMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ conversationId, userIds }: { conversationId: string; userIds: string[] }) =>
      chatApi.addConversationParticipants(conversationId, userIds),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useRemoveParticipantMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ conversationId, userId }: { conversationId: string; userId: string }) =>
      chatApi.removeConversationParticipant(conversationId, userId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};
