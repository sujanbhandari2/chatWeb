import { WidgetPanelType } from '../../../types/chat';
import { CreateGroupForm } from './CreateGroupForm';
import { EditGroupForm } from './EditGroupForm';
import { ConversationList } from '../../../features/chat-widget/sidebar/ConversationList';
import { PeopleDirectory } from '../../../features/chat-widget/sidebar/PeopleDirectory';
import { SidebarHeader } from '../../../features/chat-widget/sidebar/SidebarHeader';
import { GroupForm } from '../../../features/chat-widget/sidebar/GroupForm';
import { useChatSidebarState } from './useChatSidebarState';

function PeoplePanel(): JSX.Element {
  const {
    navigateToChats,
    filteredPeopleDirectory,
    sortedTenantPeers,
    peopleSearchQuery,
    setPeopleSearchQuery,
    openingDirectUserId,
    onOpenDirectChat,
  } = useChatSidebarState();

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

function NewGroupPanel(): JSX.Element {
  const { navigateToChatsFromNewGroup, creatingGroup } = useChatSidebarState();

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

function EditGroupPanel(): JSX.Element {
  const { navigateToChatsFromEditGroup, editingGroup } = useChatSidebarState();

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

function ChatsPanel(): JSX.Element {
  const {
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
    features,
  } = useChatSidebarState();

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
  const { user, currentPanel } = useChatSidebarState();

  if (!user) {
    return <></>;
  }

  switch (currentPanel) {
    case WidgetPanelType.PEOPLE:
      return <PeoplePanel />;
    case WidgetPanelType.NEW_GROUP:
      return <NewGroupPanel />;
    case WidgetPanelType.EDIT_GROUP:
      return <EditGroupPanel />;
    case WidgetPanelType.CHATS:
      return <ChatsPanel />;
    default: {
      const _exhaustive: never = currentPanel;
      return _exhaustive;
    }
  }
}
