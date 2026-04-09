import type { RefObject } from 'react';
import { useCallback, useMemo } from 'react';
import { useShallow } from 'zustand/react/shallow';
import { useAuthStore } from '../../../store/useAuthStore';
import { useChatSelectors } from '../../../hooks/useChatSelectors';
import { useChatRuntimeContext } from '../../../hooks/ChatRuntimeContext';
import { useWidgetFeatures } from '../../../hooks/useWidgetInitConfig';
import {
  useConversationSubtitleGetter,
  useConversationTitleGetter,
  useFilteredConversationsForSidebar,
  useFilteredPeopleDirectory,
  useGetSingleOtherParticipantId,
  useSortedConversations,
  useSortedTenantPeers
} from '../../../hooks/useChatDerived';
import { WidgetPanelType } from '../../../types/chat';
import type { ChatSidebarState } from '../../../types/chat-sidebar.types';

/** Zustand + derived selectors + navigations for the widget chat sidebar rails. */
export function useChatSidebarState(): ChatSidebarState {
  const features = useWidgetFeatures();
  const { user } = useAuthStore(useShallow((s) => ({ user: s.user })));

  const {
    widgetRailPane,
    setWidgetRailPane,
    creatingGroup,
    setGroupModalError,
    editGroupSaving,
    setEditGroupError,
    peopleSearchQuery,
    setPeopleSearchQuery,
    openingDirectUserId,
    openDirectChat,
    widgetInboxMenuOpen,
    setWidgetInboxMenuOpen,
    widgetChatSearchQuery,
    setWidgetChatSearchQuery,
    selectedConversationId,
    selectConversation,
    unreadByConversation,
    openGroupModal,
    tenantUsers,
  } = useChatSelectors((s) => ({
    widgetRailPane: s.widgetRailPane,
    setWidgetRailPane: s.setWidgetRailPane,
    creatingGroup: s.creatingGroup,
    setGroupModalError: s.setGroupModalError,
    editGroupSaving: s.editGroupSaving,
    setEditGroupError: s.setEditGroupError,
    peopleSearchQuery: s.peopleSearchQuery,
    setPeopleSearchQuery: s.setPeopleSearchQuery,
    openingDirectUserId: s.openingDirectUserId,
    openDirectChat: s.openDirectChat,
    widgetInboxMenuOpen: s.widgetInboxMenuOpen,
    setWidgetInboxMenuOpen: s.setWidgetInboxMenuOpen,
    widgetChatSearchQuery: s.widgetChatSearchQuery,
    setWidgetChatSearchQuery: s.setWidgetChatSearchQuery,
    selectedConversationId: s.selectedConversationId,
    selectConversation: s.selectConversation,
    unreadByConversation: s.unreadByConversation,
    openGroupModal: s.openGroupModal,
    tenantUsers: s.tenantUsers,
  }));

  const { chatsListOverflowMenuRef } = useChatRuntimeContext();
  const sortedConversations = useSortedConversations();
  const sortedTenantPeers = useSortedTenantPeers();
  const filteredConversationsForSidebar = useFilteredConversationsForSidebar();
  const filteredPeopleDirectory = useFilteredPeopleDirectory();
  const getSingleOtherParticipantId = useGetSingleOtherParticipantId();
  const getConversationTitle = useConversationTitleGetter();
  const getConversationSubtitle = useConversationSubtitleGetter();

  const isPeerOnline = useMemo(
    () => (userId: string): boolean => tenantUsers.find((u) => u.id === userId)?.isOnline ?? false,
    [tenantUsers]
  );

  const navigateToChats = useCallback(() => {
    setWidgetRailPane(WidgetPanelType.CHATS);
    setPeopleSearchQuery('');
  }, [setWidgetRailPane, setPeopleSearchQuery]);

  const navigateToChatsFromNewGroup = useCallback(() => {
    if (!creatingGroup) {
      setWidgetRailPane(WidgetPanelType.CHATS);
      setGroupModalError('');
    }
  }, [creatingGroup, setWidgetRailPane, setGroupModalError]);

  const navigateToChatsFromEditGroup = useCallback(() => {
    if (!editGroupSaving) {
      setWidgetRailPane(WidgetPanelType.CHATS);
      setEditGroupError('');
    }
  }, [editGroupSaving, setWidgetRailPane, setEditGroupError]);

  const navigateToPeople = useCallback(() => {
    setWidgetInboxMenuOpen(false);
    setPeopleSearchQuery('');
    setWidgetRailPane(WidgetPanelType.PEOPLE);
  }, [setWidgetInboxMenuOpen, setPeopleSearchQuery, setWidgetRailPane]);

  const navigateToNewGroup = useCallback(() => {
    setWidgetInboxMenuOpen(false);
    openGroupModal();
  }, [setWidgetInboxMenuOpen, openGroupModal]);

  const selectedForList = selectedConversationId.trim() === '' ? null : selectedConversationId;

  return {
    user,
    currentPanel: widgetRailPane,
    features,

    navigateToChats,
    filteredPeopleDirectory,
    sortedTenantPeers,
    peopleSearchQuery,
    setPeopleSearchQuery,
    openingDirectUserId,
    onOpenDirectChat: openDirectChat,

    navigateToChatsFromNewGroup,
    creatingGroup,

    navigateToChatsFromEditGroup,
    editingGroup: editGroupSaving,

    filteredConversations: filteredConversationsForSidebar,
    sortedConversations,
    chatSearchQuery: widgetChatSearchQuery,
    setChatSearchQuery: setWidgetChatSearchQuery,
    selectedConversationId: selectedForList,
    selectConversation,
    unreadByConversation,
    getSingleOtherParticipantId,
    getConversationTitle,
    getConversationSubtitle,
    isPeerOnline,
    menuOpen: widgetInboxMenuOpen,
    setMenuOpen: setWidgetInboxMenuOpen,
    overflowMenuRef: chatsListOverflowMenuRef as RefObject<HTMLDivElement>,
    navigateToPeople,
    navigateToNewGroup,
  };
}

export type { ChatSidebarState } from '../../../types/chat-sidebar.types';
