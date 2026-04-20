import { WidgetPanelType } from '../../../types/chat';
import type {
  ChatSidebarChatsPanelProps,
  ChatSidebarEditGroupPanelProps,
  ChatSidebarNewGroupPanelProps,
  ChatSidebarPeoplePanelProps
} from '../../../types/chat-sidebar.types';
import { CreateGroupForm } from './CreateGroupForm';
import { EditGroupForm } from './EditGroupForm';
import { ConversationList } from '../../../features/chat-widget/sidebar/ConversationList';
import { PeopleDirectory } from '../../../features/chat-widget/sidebar/PeopleDirectory';
import { SidebarHeader } from '../../../features/chat-widget/sidebar/SidebarHeader';
import { GroupForm } from '../../../features/chat-widget/sidebar/GroupForm';
import { useChatStore } from '../../../store/useChatStore';
import { useChatSidebarState } from './useChatSidebarState';

function PeoplePanel({
  navigateToChats,
  filteredPeopleDirectory,
  sortedTenantPeers,
  peopleSearchQuery,
  setPeopleSearchQuery,
  openingDirectUserId,
  onOpenDirectChat
}: ChatSidebarPeoplePanelProps): JSX.Element {
  return (
    <>
      <SidebarHeader
        title="People"
        subtitle="Everyone in your organization"
        onBack={navigateToChats}
      />
      <div className="left-rail-scroll left-rail-scroll--widget-order">
        <PeopleDirectory
          sortedPeers={sortedTenantPeers}
          filteredPeople={filteredPeopleDirectory}
          searchQuery={peopleSearchQuery}
          onSearchChange={setPeopleSearchQuery}
          openingUserId={openingDirectUserId}
          onOpenChat={onOpenDirectChat}
        />
      </div>
    </>
  );
}

function NewGroupPanel({
  navigateToChatsFromNewGroup,
  creatingGroup
}: ChatSidebarNewGroupPanelProps): JSX.Element {
  return (
    <>
      <SidebarHeader
        title="New group"
        subtitle="Name the group and add at least two people. You are added automatically."
        onBack={navigateToChatsFromNewGroup}
        backDisabled={creatingGroup}
      />
      <div className="left-rail-scroll left-rail-scroll--widget-order">
        <GroupForm variant="create">
          <CreateGroupForm />
        </GroupForm>
      </div>
    </>
  );
}

function EditGroupPanel({
  navigateToChatsFromEditGroup,
  editingGroup
}: ChatSidebarEditGroupPanelProps): JSX.Element {
  return (
    <>
      <SidebarHeader
        title="Edit group"
        subtitle="Rename the group, add people, or remove other members. Use Leave group below to exit yourself."
        onBack={navigateToChatsFromEditGroup}
        backDisabled={editingGroup}
        backAriaLabel="Back to chat"
      />
      <div className="left-rail-scroll left-rail-scroll--widget-order">
        <GroupForm variant="edit">
          <EditGroupForm />
        </GroupForm>
      </div>
    </>
  );
}

function ChatsPanel({
  filteredConversations,
  sortedConversations,
  chatSearchQuery,
  setChatSearchQuery,
  selectedConversationId,
  selectConversation,
  unreadByConversation,
  getSingleOtherParticipantId,
  getConversationTitle,
  getConversationSubtitle,
  isPeerOnline,
  menuOpen,
  setMenuOpen,
  overflowMenuRef,
  navigateToPeople,
  navigateToNewGroup,
  features
}: ChatSidebarChatsPanelProps): JSX.Element {
  return (
    <div className="left-rail-scroll left-rail-scroll--widget-order">
      <ConversationList
        conversations={filteredConversations}
        allConversations={sortedConversations}
        searchQuery={chatSearchQuery}
        onSearchChange={setChatSearchQuery}
        selectedConversationId={selectedConversationId}
        onSelectConversation={selectConversation}
        unreadByConversation={unreadByConversation}
        getSingleOtherParticipantId={getSingleOtherParticipantId}
        getConversationTitle={getConversationTitle}
        getConversationSubtitle={getConversationSubtitle}
        isPeerOnline={isPeerOnline}
        menuOpen={menuOpen}
        onMenuToggle={setMenuOpen}
        overflowMenuRef={overflowMenuRef}
        onNavigateToPeople={navigateToPeople}
        onNavigateToNewGroup={navigateToNewGroup}
        features={features}
      />
    </div>
  );
}

/** Widget left rail: chats list, people directory, create/edit group flows. */
export function ChatSidebar(): JSX.Element | null {
  const state = useChatSidebarState();
  const chatLoadError = useChatStore((s) => s.error);

  if (!state.user) {
    return null;
  }

  const errorBanner =
    chatLoadError.trim() !== '' ? (
      <p className="error-banner" role="alert" style={{ margin: '0.5rem 0.75rem 0', flexShrink: 0 }}>
        {chatLoadError}
      </p>
    ) : null;

  switch (state.currentPanel) {
    case WidgetPanelType.PEOPLE:
      return (
        <>
          {errorBanner}
          <PeoplePanel
            navigateToChats={state.navigateToChats}
            filteredPeopleDirectory={state.filteredPeopleDirectory}
            sortedTenantPeers={state.sortedTenantPeers}
            peopleSearchQuery={state.peopleSearchQuery}
            setPeopleSearchQuery={state.setPeopleSearchQuery}
            openingDirectUserId={state.openingDirectUserId}
            onOpenDirectChat={state.onOpenDirectChat}
          />
        </>
      );
    case WidgetPanelType.NEW_GROUP:
      return (
        <>
          {errorBanner}
          <NewGroupPanel
            navigateToChatsFromNewGroup={state.navigateToChatsFromNewGroup}
            creatingGroup={state.creatingGroup}
          />
        </>
      );
    case WidgetPanelType.EDIT_GROUP:
      return (
        <>
          {errorBanner}
          <EditGroupPanel
            navigateToChatsFromEditGroup={state.navigateToChatsFromEditGroup}
            editingGroup={state.editingGroup}
          />
        </>
      );
    case WidgetPanelType.CHATS:
      return (
        <>
          {errorBanner}
          <ChatsPanel
            filteredConversations={state.filteredConversations}
            sortedConversations={state.sortedConversations}
            chatSearchQuery={state.chatSearchQuery}
            setChatSearchQuery={state.setChatSearchQuery}
            selectedConversationId={state.selectedConversationId}
            selectConversation={state.selectConversation}
            unreadByConversation={state.unreadByConversation}
            getSingleOtherParticipantId={state.getSingleOtherParticipantId}
            getConversationTitle={state.getConversationTitle}
            getConversationSubtitle={state.getConversationSubtitle}
            isPeerOnline={state.isPeerOnline}
            menuOpen={state.menuOpen}
            setMenuOpen={state.setMenuOpen}
            overflowMenuRef={state.overflowMenuRef}
            navigateToPeople={state.navigateToPeople}
            navigateToNewGroup={state.navigateToNewGroup}
            features={state.features}
          />
        </>
      );
    default:
      return null;
  }
}
