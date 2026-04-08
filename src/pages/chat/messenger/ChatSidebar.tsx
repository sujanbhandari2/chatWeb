import type { RefObject } from 'react';
import { isGlobalConversation, userDisplayName, userInitials } from '../../../utils/chat.utils';
import { useAuthStore } from '../../../store/useAuthStore';
import { useChatSelectors } from '../../../hooks/useChatSelectors';
import { AvatarWithPresence } from '../../../features/chat/messenger-ui';
import { useChatRuntimeContext } from '../../../hooks/ChatRuntimeContext';

import {
  useConversationSubtitleGetter,
  useConversationTitleGetter,
  useFilteredConversationsForSidebar,
  useFilteredPeopleDirectory,
  useGetSingleOtherParticipantId,
  useSortedConversations,
  useSortedTenantPeers
} from '../../../hooks/useChatDerived';
import { useShallow } from 'zustand/react/shallow';
import { CreateGroupForm } from './CreateGroupForm';
import { EditGroupForm } from './EditGroupForm';

/** Left column: conversation list, people directory, and inline group create/edit flows. */
export function ChatSidebar(): JSX.Element {
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
  const isPeerOnline = (userId: string): boolean =>
    tenantUsers.find((u) => u.id === userId)?.isOnline ?? false;

  if (!user) {
    return <></>;
  }

  const overflowMenuRef = chatsListOverflowMenuRef as RefObject<HTMLDivElement>;

  return (
    <>
      {widgetRailPane === 'people' ? (
        <div className="left-header left-header--widget-people">
          <button
            type="button"
            className="widget-people-back"
            onClick={() => {
              setWidgetRailPane('chats');
              setPeopleSearchQuery('');
            }}
            aria-label="Back to chats"
          >
            ←
          </button>
          <div className="left-header-main">
            <h2>People</h2>
            <p className="widget-people-subtitle">Everyone in your organization</p>
          </div>
        </div>
      ) : widgetRailPane === 'new-group' ? (
        <div className="left-header left-header--widget-people">
          <button
            type="button"
            className="widget-people-back"
            onClick={() => {
              if (!creatingGroup) {
                setWidgetRailPane('chats');
                setGroupModalError('');
              }
            }}
            aria-label="Back to chats"
          >
            ←
          </button>
          <div className="left-header-main">
            <h2>New group</h2>
            <p className="widget-people-subtitle">
              Name the group and add at least two people. You are added automatically.
            </p>
          </div>
        </div>
      ) : widgetRailPane === 'edit-group' ? (
        <div className="left-header left-header--widget-people">
          <button
            type="button"
            className="widget-people-back"
            onClick={() => {
              if (!editGroupSaving) {
                setWidgetRailPane('chats');
                setEditGroupError('');
              }
            }}
            aria-label="Back to chat"
          >
            ←
          </button>
          <div className="left-header-main">
            <h2>Edit group</h2>
            <p className="widget-people-subtitle">
              Rename the group, add people, or remove other members. Use <strong>Leave group</strong> below to exit
              yourself.
            </p>
          </div>
        </div>
      ) : null}

      <div className="left-rail-scroll left-rail-scroll--widget-order">
        {widgetRailPane === 'people' && (
          <section className="quick-chat" aria-label="All people in your tenant">
            <label className="quick-chat-search-label">
              <span className="visually-hidden">Search people by name or email</span>
              <input
                className="quick-chat-search"
                type="search"
                value={peopleSearchQuery}
                onChange={(event) => setPeopleSearchQuery(event.target.value)}
                placeholder="Search people…"
                autoComplete="off"
                spellCheck={false}
                aria-label="Search all people"
              />
            </label>
            <div className="quick-list">
              {sortedTenantPeers.length === 0 && (
                <span className="muted-text">No other users in this tenant yet.</span>
              )}
              {sortedTenantPeers.length > 0 && filteredPeopleDirectory.length === 0 && (
                <span className="muted-text">No one matches &quot;{peopleSearchQuery.trim()}&quot;.</span>
              )}
              {filteredPeopleDirectory.map((tenantUser) => (
                <button
                  key={tenantUser.id}
                  type="button"
                  className="quick-item"
                  onClick={() => void openDirectChat(tenantUser)}
                  disabled={openingDirectUserId === tenantUser.id}
                  aria-label={`Open chat with ${userDisplayName(tenantUser)}`}
                >
                  <AvatarWithPresence online={tenantUser.isOnline}>
                    <div className="avatar-mini">{userInitials(tenantUser)}</div>
                  </AvatarWithPresence>
                  <div className="quick-user-meta">
                    <strong>{userDisplayName(tenantUser)}</strong>
                    <span>
                      {tenantUser.status ?? '—'} · {tenantUser.isOnline ? 'Active' : 'Away'}
                    </span>
                    <span className="quick-user-email">{tenantUser.email}</span>
                  </div>
                  <span className="quick-item-action">
                    {openingDirectUserId === tenantUser.id ? 'Opening…' : 'Chat →'}
                  </span>
                </button>
              ))}
            </div>
          </section>
        )}

        {widgetRailPane === 'new-group' && (
          <section className="widget-new-group-page" aria-label="Create new group">
            <CreateGroupForm />
          </section>
        )}

        {widgetRailPane === 'edit-group' && (
          <section className="widget-new-group-page" aria-label="Edit group">
            <EditGroupForm />
          </section>
        )}

        {widgetRailPane === 'chats' && (
          <section className="conversation-list" aria-label="Your conversations">
            <div className="widget-chats-search-row">
              <div className="widget-chats-menu-wrap" ref={overflowMenuRef}>
                <button
                  type="button"
                  className="chat-header-menu-btn widget-chats-overflow-btn"
                  aria-expanded={widgetInboxMenuOpen}
                  aria-haspopup="menu"
                  aria-label="More options"
                  onClick={() => setWidgetInboxMenuOpen((open) => !open)}
                >
                  ⋮
                </button>
                {widgetInboxMenuOpen && (
                  <div className="rail-menu-dropdown rail-menu-dropdown--widget-chats-row" role="menu">
                    <button
                      type="button"
                      role="menuitem"
                      className="rail-menu-item rail-menu-item--widget-suggest"
                      onClick={() => {
                        setWidgetInboxMenuOpen(false);
                        setPeopleSearchQuery('');
                        setWidgetRailPane('people');
                      }}
                    >
                      Suggested people
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      className="rail-menu-item rail-menu-item--widget-suggest"
                      onClick={() => {
                        setWidgetInboxMenuOpen(false);
                        openGroupModal();
                      }}
                    >
                      New group
                    </button>
                  </div>
                )}
              </div>
              <label className="widget-chats-search-label">
                <span className="visually-hidden">Search your chats</span>
                <input
                  className="quick-chat-search widget-chats-search-input"
                  type="search"
                  value={widgetChatSearchQuery}
                  onChange={(event) => setWidgetChatSearchQuery(event.target.value)}
                  placeholder="Search chats…"
                  autoComplete="off"
                  spellCheck={false}
                  aria-label="Search chats"
                />
              </label>
            </div>
            {filteredConversationsForSidebar.map((conversation) => {
              const unreadCount = unreadByConversation[conversation.id] ?? 0;
              const listOtherId = getSingleOtherParticipantId(conversation);
              const listAvatar = (
                <div className="avatar-mini">
                  {isGlobalConversation(conversation)
                    ? 'ALL'
                    : userInitials(conversation.participants[0]?.user ?? { name: null, email: '?' })}
                </div>
              );

              const convTitle = getConversationTitle(conversation);

              return (
                <button
                  key={conversation.id}
                  type="button"
                  className={`conversation-item ${conversation.id === selectedConversationId ? 'active' : ''}${
                    unreadCount > 0 ? ' conversation-item--unread' : ''
                  }`}
                  aria-label={
                    unreadCount > 0
                      ? `${convTitle}, ${unreadCount} unread message${unreadCount === 1 ? '' : 's'}`
                      : convTitle
                  }
                  onClick={() => void selectConversation(conversation.id)}
                >
                  {listOtherId !== undefined && !isGlobalConversation(conversation) ? (
                    <AvatarWithPresence online={isPeerOnline(listOtherId)}>{listAvatar}</AvatarWithPresence>
                  ) : (
                    listAvatar
                  )}
                  <div className="conversation-meta">
                    <div className="conversation-meta-top">
                      <strong>{convTitle}</strong>
                      {unreadCount > 0 && (
                        <span className="unread-badge" aria-hidden>
                          {unreadCount > 99 ? '99+' : unreadCount}
                        </span>
                      )}
                    </div>
                    <span>{getConversationSubtitle(conversation)}</span>
                  </div>
                </button>
              );
            })}
            {filteredConversationsForSidebar.length === 0 && sortedConversations.length > 0 && (
              <p className="muted-text widget-chats-empty-hint">No chats match your search.</p>
            )}
            {sortedConversations.length === 0 && (
              <p className="muted-text widget-chats-empty-hint">
                No chats yet. Tap ⋮ and choose Suggested people to browse everyone.
              </p>
            )}
          </section>
        )}
      </div>
    </>
  );
}
