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
        subtitle="Chat profiles for this tenant (GET /api/v1/chat/users)"
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
        subtitle="Pick at least two other members. The Vitafy API stores participants only — this label is for your reference in the app."
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
        title="Add to group"
        subtitle="Only adding members is supported (POST …/participants). Renaming, removing members, and leaving are not in the chat API."
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
export function ChatSidebar(): JSX.Element {
  const state = useChatSidebarState();

  if (!state.user) {
    return <></>;
  }

  switch (state.currentPanel) {
    case WidgetPanelType.PEOPLE:
      return (
        <PeoplePanel
          navigateToChats={state.navigateToChats}
          filteredPeopleDirectory={state.filteredPeopleDirectory}
          sortedTenantPeers={state.sortedTenantPeers}
          peopleSearchQuery={state.peopleSearchQuery}
          setPeopleSearchQuery={state.setPeopleSearchQuery}
          openingDirectUserId={state.openingDirectUserId}
          onOpenDirectChat={state.onOpenDirectChat}
        />
      );
    case WidgetPanelType.NEW_GROUP:
      return (
        <NewGroupPanel
          navigateToChatsFromNewGroup={state.navigateToChatsFromNewGroup}
          creatingGroup={state.creatingGroup}
        />
      );
    case WidgetPanelType.EDIT_GROUP:
      return (
        <EditGroupPanel
          navigateToChatsFromEditGroup={state.navigateToChatsFromEditGroup}
          editingGroup={state.editingGroup}
        />
      );
    case WidgetPanelType.CHATS:
      return (
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
      );
    default: {
      const _exhaustive: never = state.currentPanel;
      return _exhaustive;
    }
  }
}
