import { useCallback, useMemo } from 'react';
import {
  isGlobalConversation,
  isGroupConversation,
  userDisplayName
} from '../utils/chat.utils';
import type { Conversation, TenantUser } from '../types/chat';
import { useAuthStore } from '../store/useAuthStore';
import { useChatSelectors } from './useChatSelectors';
import { useChatStore } from '../store/useChatStore';

export function useUsersById(): Map<string, TenantUser> {
  const tenantUsers = useChatStore((s) => s.tenantUsers);
  return useMemo(() => new Map(tenantUsers.map((item) => [item.id, item])), [tenantUsers]);
}

/** Stable `(userId) => isOnline` from tenant directory (sidebar + thread). */
export function useTenantUserOnlineLookup(): (userId: string) => boolean {
  const usersById = useUsersById();
  return useCallback((userId: string) => usersById.get(userId)?.isOnline ?? false, [usersById]);
}

export function useSelectedConversation(): Conversation | null {
  const { conversations, selectedConversationId } = useChatSelectors((s) => ({
    conversations: s.conversations,
    selectedConversationId: s.selectedConversationId,
  }));
  return useMemo(
    () => conversations.find((conversation) => conversation.id === selectedConversationId) ?? null,
    [conversations, selectedConversationId]
  );
}

export function useSortedConversations(): Conversation[] {
  const { conversations, unreadByConversation } = useChatSelectors((s) => ({
    conversations: s.conversations,
    unreadByConversation: s.unreadByConversation,
  }));
  return useMemo(() => {
    return [...conversations].sort((a, b) => {
      const unreadA = (unreadByConversation[a.id] ?? 0) > 0 ? 1 : 0;
      const unreadB = (unreadByConversation[b.id] ?? 0) > 0 ? 1 : 0;
      if (unreadA !== unreadB) {
        return unreadB - unreadA;
      }
      const ta = new Date(a.updatedAt).getTime();
      const tb = new Date(b.updatedAt).getTime();
      // Oldest → newest so the latest chat appears at the bottom.
      return ta - tb;
    });
  }, [conversations, unreadByConversation]);
}

export function useSortedTenantPeers(): TenantUser[] {
  const tenantUsers = useChatStore((s) => s.tenantUsers);
  const userId = useAuthStore((s) => s.user?.id);
  return useMemo(() => {
    const byId = new Map<string, TenantUser>();
    for (const tenantUser of tenantUsers) {
      if (tenantUser.id === userId) {
        continue;
      }
      if (!byId.has(tenantUser.id)) {
        byId.set(tenantUser.id, tenantUser);
      }
    }
    return [...byId.values()].sort((a, b) => {
      if (a.isOnline !== b.isOnline) {
        return a.isOnline ? -1 : 1;
      }
      return userDisplayName(a).localeCompare(userDisplayName(b));
    });
  }, [tenantUsers, userId]);
}

export function usePeerIdsWithDirectChat(): Set<string> {
  const conversations = useChatStore((s) => s.conversations);
  const user = useAuthStore((s) => s.user);
  return useMemo(() => {
    const ids = new Set<string>();
    if (!user) {
      return ids;
    }
    for (const c of conversations) {
      if (isGlobalConversation(c)) {
        continue;
      }
      const others = c.participants.filter((p) => p.userId !== user.id);
      if (others.length === 1) {
        ids.add(others[0].userId);
      }
    }
    return ids;
  }, [conversations, user]);
}

export function usePeersWithoutDirectChat(): TenantUser[] {
  const sortedTenantPeers = useSortedTenantPeers();
  const peerIdsWithDirectChat = usePeerIdsWithDirectChat();
  return useMemo(
    () => sortedTenantPeers.filter((p) => !peerIdsWithDirectChat.has(p.id)),
    [sortedTenantPeers, peerIdsWithDirectChat]
  );
}

export function useConversationTitleGetter(): (conversation: Conversation) => string {
  const user = useAuthStore((s) => s.user);
  return useMemo(() => {
    return (conversation: Conversation): string => {
      if (isGlobalConversation(conversation)) {
        return 'System Broadcast (All Users)';
      }
      if (conversation.title?.trim()) {
        return conversation.title.trim();
      }
      if (!user) {
        return 'Conversation';
      }
      const others = conversation.participants.filter((item) => item.userId !== user.id);
      if (others.length === 0) {
        return 'Just You';
      }
      if (others.length === 1) {
        return userDisplayName(others[0].user);
      }
      return `${userDisplayName(others[0].user)} + ${others.length - 1}`;
    };
  }, [user]);
}

export function useConversationSubtitleGetter(): (conversation: Conversation) => string {
  const user = useAuthStore((s) => s.user);
  const usersById = useUsersById();
  return useMemo(() => {
    const isPeerOnline = (userId: string): boolean => usersById.get(userId)?.isOnline ?? false;
    return (conversation: Conversation): string => {
      const n = conversation.participants.length;
      if (isGlobalConversation(conversation)) {
        return `${n} members`;
      }
      if (!user) {
        return `${n} members`;
      }
      const others = conversation.participants.filter((item) => item.userId !== user.id);
      const treatAsGroup = isGroupConversation(conversation) || others.length > 1;
      if (treatAsGroup) {
        return `${n} members · Group`;
      }
      if (others.length === 1) {
        const online = isPeerOnline(others[0].userId);
        return online ? 'Direct · Online' : 'Direct · Away';
      }
      if (others.length === 0) {
        return 'Only you';
      }
      return `${n} members`;
    };
  }, [user, usersById]);
}

/** Conversations shown in the sidebar, with optional search filter. */
export function useFilteredConversationsForSidebar(): Conversation[] {
  const sortedConversations = useSortedConversations();
  const widgetChatSearchQuery = useChatStore((s) => s.widgetChatSearchQuery);
  const usersById = useUsersById();
  const getConversationTitle = useConversationTitleGetter();
  const getConversationSubtitle = useConversationSubtitleGetter();
  return useMemo(() => {
    const q = widgetChatSearchQuery.trim().toLowerCase();
    if (!q) {
      return sortedConversations;
    }
    return sortedConversations.filter((c) => {
      const title = getConversationTitle(c).toLowerCase();
      const sub = getConversationSubtitle(c).toLowerCase();
      if (title.includes(q) || sub.includes(q)) {
        return true;
      }
      for (const p of c.participants) {
        const tu = usersById.get(p.userId);
        const name = tu ? userDisplayName(tu).toLowerCase() : (p.user?.name ?? '').toLowerCase();
        const email = (tu?.email ?? p.user?.email ?? '').toLowerCase();
        if (name.includes(q) || email.includes(q) || p.userId.toLowerCase().includes(q)) {
          return true;
        }
      }
      return false;
    });
  }, [sortedConversations, widgetChatSearchQuery, usersById, getConversationTitle, getConversationSubtitle]);
}

/** Tenant peers on the People pane, filtered by search. */
export function useFilteredPeopleDirectory(): TenantUser[] {
  const sortedTenantPeers = useSortedTenantPeers();
  const peopleSearchQuery = useChatStore((s) => s.peopleSearchQuery);
  return useMemo(() => {
    const q = peopleSearchQuery.trim().toLowerCase();
    if (!q) {
      return sortedTenantPeers;
    }
    return sortedTenantPeers.filter((peer) => {
      const name = userDisplayName(peer).toLowerCase();
      const email = peer.email.toLowerCase();
      const status = (peer.status ?? '').toLowerCase();
      return (
        name.includes(q) ||
        email.includes(q) ||
        status.includes(q) ||
        peer.id.toLowerCase().includes(q)
      );
    });
  }, [sortedTenantPeers, peopleSearchQuery]);
}

export function useFilteredGroupPickerPeers(): TenantUser[] {
  const sortedTenantPeers = useSortedTenantPeers();
  const { groupSelectedUserIds, groupPickerSearch } = useChatSelectors((s) => ({
    groupSelectedUserIds: s.groupSelectedUserIds,
    groupPickerSearch: s.groupPickerSearch,
  }));
  return useMemo(() => {
    const selected = new Set(groupSelectedUserIds);
    const q = groupPickerSearch.trim().toLowerCase();
    return sortedTenantPeers
      .filter((p) => !selected.has(p.id))
      .filter((p) => {
        if (!q) {
          return true;
        }
        return (
          userDisplayName(p).toLowerCase().includes(q) ||
          p.email.toLowerCase().includes(q) ||
          (p.status ?? '').toLowerCase().includes(q)
        );
      });
  }, [sortedTenantPeers, groupSelectedUserIds, groupPickerSearch]);
}

export function useFilteredEditGroupPickerPeers(): TenantUser[] {
  const sortedTenantPeers = useSortedTenantPeers();
  const { editGroupParticipantIds, editGroupPickerSearch } = useChatSelectors((s) => ({
    editGroupParticipantIds: s.editGroupParticipantIds,
    editGroupPickerSearch: s.editGroupPickerSearch,
  }));
  return useMemo(() => {
    const memberSet = new Set(editGroupParticipantIds);
    const q = editGroupPickerSearch.trim().toLowerCase();
    return sortedTenantPeers
      .filter((p) => !memberSet.has(p.id))
      .filter((p) => {
        if (!q) {
          return true;
        }
        return (
          userDisplayName(p).toLowerCase().includes(q) ||
          p.email.toLowerCase().includes(q) ||
          (p.status ?? '').toLowerCase().includes(q)
        );
      });
  }, [sortedTenantPeers, editGroupParticipantIds, editGroupPickerSearch]);
}

export function useGetSingleOtherParticipantId(): (conversation: Conversation) => string | undefined {
  const user = useAuthStore((s) => s.user);
  return useMemo(() => {
    return (conversation: Conversation): string | undefined => {
      if (!user || isGlobalConversation(conversation)) {
        return undefined;
      }
      const others = conversation.participants.filter((p) => p.userId !== user.id);
      return others.length === 1 ? others[0].userId : undefined;
    };
  }, [user]);
}

export function useSelectedDirectPeerId(): string | undefined {
  const selectedConversation = useSelectedConversation();
  const user = useAuthStore((s) => s.user);
  return useMemo(() => {
    if (!selectedConversation || !user || isGlobalConversation(selectedConversation)) {
      return undefined;
    }
    const others = selectedConversation.participants.filter((p) => p.userId !== user.id);
    return others.length === 1 ? others[0].userId : undefined;
  }, [selectedConversation, user]);
}

export function useDisplayNameForParticipant(): (userId: string) => string {
  const usersById = useUsersById();
  const selectedConversation = useSelectedConversation();
  return useMemo(() => {
    return (userId: string): string => {
      const tenant = usersById.get(userId);
      if (tenant) {
        return userDisplayName(tenant);
      }
      const fromConv = selectedConversation?.participants.find((p) => p.userId === userId)?.user;
      if (fromConv) {
        return userDisplayName(fromConv);
      }
      return userId.slice(0, 8);
    };
  }, [usersById, selectedConversation]);
}
