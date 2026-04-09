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
