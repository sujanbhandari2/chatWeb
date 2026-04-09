import type { RefObject } from 'react';
import type { WidgetFeatures } from '../schemas/widget.schemas';
import type { AuthUser, Conversation, TenantUser, WidgetPanelType } from './chat';

export type ChatSidebarState = {
  user: AuthUser | null;
  currentPanel: WidgetPanelType;
  features: WidgetFeatures;

  navigateToChats: () => void;
  filteredPeopleDirectory: TenantUser[];
  sortedTenantPeers: TenantUser[];
  peopleSearchQuery: string;
  setPeopleSearchQuery: (q: string) => void;
  openingDirectUserId: string;
  onOpenDirectChat: (user: TenantUser) => Promise<void>;

  navigateToChatsFromNewGroup: () => void;
  creatingGroup: boolean;

  navigateToChatsFromEditGroup: () => void;
  editingGroup: boolean;

  filteredConversations: Conversation[];
  sortedConversations: Conversation[];
  chatSearchQuery: string;
  setChatSearchQuery: (q: string) => void;
  selectedConversationId: string | null;
  selectConversation: (id: string) => Promise<void>;
  unreadByConversation: Record<string, number>;
  getSingleOtherParticipantId: (conversation: Conversation) => string | undefined;
  getConversationTitle: (conversation: Conversation) => string;
  getConversationSubtitle: (conversation: Conversation) => string;
  isPeerOnline: (userId: string) => boolean;
  menuOpen: boolean;
  setMenuOpen: (v: boolean | ((o: boolean) => boolean)) => void;
  overflowMenuRef: RefObject<HTMLDivElement>;
  navigateToPeople: () => void;
  navigateToNewGroup: () => void;
};

export type ChatSidebarPeoplePanelProps = Pick<
  ChatSidebarState,
  | 'navigateToChats'
  | 'filteredPeopleDirectory'
  | 'sortedTenantPeers'
  | 'peopleSearchQuery'
  | 'setPeopleSearchQuery'
  | 'openingDirectUserId'
  | 'onOpenDirectChat'
>;

export type ChatSidebarNewGroupPanelProps = Pick<
  ChatSidebarState,
  'navigateToChatsFromNewGroup' | 'creatingGroup'
>;

export type ChatSidebarEditGroupPanelProps = Pick<
  ChatSidebarState,
  'navigateToChatsFromEditGroup' | 'editingGroup'
>;

export type ChatSidebarChatsPanelProps = Pick<
  ChatSidebarState,
  | 'filteredConversations'
  | 'sortedConversations'
  | 'chatSearchQuery'
  | 'setChatSearchQuery'
  | 'selectedConversationId'
  | 'selectConversation'
  | 'unreadByConversation'
  | 'getSingleOtherParticipantId'
  | 'getConversationTitle'
  | 'getConversationSubtitle'
  | 'isPeerOnline'
  | 'menuOpen'
  | 'setMenuOpen'
  | 'overflowMenuRef'
  | 'navigateToPeople'
  | 'navigateToNewGroup'
  | 'features'
>;
