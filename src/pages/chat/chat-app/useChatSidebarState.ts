import type { RefObject } from 'react';
import { useCallback } from 'react';
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
  useSortedTenantPeers,
  useTenantUserOnlineLookup
} from '../../../hooks/useChatDerived';
import { WidgetPanelType } from '../../../types/chat';
import type { ChatSidebarState } from '../../../types/chat-sidebar.types';
import { selectSidebarRails } from '../../../store/chat/chat-selectors';

/** Zustand + derived selectors + navigations for the widget chat sidebar rails. */
export function useChatSidebarState(): ChatSidebarState {
  const features = useWidgetFeatures();
  const { user } = useAuthStore(useShallow((s) => ({ user: s.user })));

  const {
    widgetRailPane,
    setWidgetRailPane,
    creatingGroup,
    editGroupSaving,
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
    exitNewGroupRailToChats,
    exitEditGroupRailToChats,
  } = useChatSelectors(selectSidebarRails);

  const { chatsListOverflowMenuRef } = useChatRuntimeContext();
  const sortedConversations = useSortedConversations();
  const sortedTenantPeers = useSortedTenantPeers();
  const filteredConversationsForSidebar = useFilteredConversationsForSidebar();
  const filteredPeopleDirectory = useFilteredPeopleDirectory();
  const getSingleOtherParticipantId = useGetSingleOtherParticipantId();
  const getConversationTitle = useConversationTitleGetter();
  const getConversationSubtitle = useConversationSubtitleGetter();
  const isPeerOnline = useTenantUserOnlineLookup();

  const navigateToChats = useCallback(() => {
    setWidgetRailPane(WidgetPanelType.CHATS);
    setPeopleSearchQuery('');
  }, [setWidgetRailPane, setPeopleSearchQuery]);

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

    navigateToChatsFromNewGroup: exitNewGroupRailToChats,
    creatingGroup,

    navigateToChatsFromEditGroup: exitEditGroupRailToChats,
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
