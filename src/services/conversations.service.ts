import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as conversationsApi from '../api/conversations.api';
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
  return useQuery({
    queryKey: conversationKeys.list(),
    queryFn: () => {
      if (!userId) {
        return Promise.resolve([]);
      }
      return conversationsApi.listConversations(userId);
    },
    enabled: !!token && !!userId
  });
};

export const useMessagesQuery = (conversationId: string) => {
  const token = useAuthStore((s) => s.token);
  return useQuery({
    queryKey: conversationKeys.messages(conversationId),
    queryFn: () =>
      conversationsApi.getMessagesPage(conversationId).then((p) => p.data.map(normalizeMessage)),
    enabled: !!token && !!conversationId
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
    if (!token || !conversationId) {
      return;
    }
    void qc.prefetchQuery({
      queryKey: conversationKeys.messages(conversationId),
      queryFn: () =>
        conversationsApi.getMessagesPage(conversationId).then((p) => p.data.map(normalizeMessage))
    });
  };
};

export const useCreateDirectConversationMutation = () => {
  const qc = useQueryClient();
  const selfId = useAuthStore((s) => s.user?.id);
  return useMutation({
    mutationFn: (otherUserId: string) => {
      if (!selfId) {
        return Promise.reject(new Error('Not signed in'));
      }
      return conversationsApi.createDirectConversation(selfId, otherUserId);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useCreateGroupConversationMutation = () => {
  const qc = useQueryClient();
  const selfId = useAuthStore((s) => s.user?.id);
  return useMutation({
    mutationFn: ({ title, participantIds }: { title: string; participantIds: string[] }) => {
      if (!selfId) {
        return Promise.reject(new Error('Not signed in'));
      }
      return conversationsApi.createGroupConversation(title, selfId, participantIds);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useDeleteConversationMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (conversationId: string) => conversationsApi.deleteConversationById(conversationId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useUpdateConversationMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ conversationId, title }: { conversationId: string; title: string }) =>
      conversationsApi.updateConversationById(conversationId, { title }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useAddParticipantsMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      conversationId,
      userIds,
      actorUserId,
      conversationType
    }: {
      conversationId: string;
      userIds: string[];
      actorUserId?: string;
      conversationType: string;
    }) =>
      conversationsApi.addConversationParticipants(conversationId, userIds, {
        actorUserId,
        conversationType
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};

export const useRemoveParticipantMutation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ conversationId, userId }: { conversationId: string; userId: string }) =>
      conversationsApi.removeConversationParticipant(conversationId, userId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: conversationKeys.list() })
  });
};
