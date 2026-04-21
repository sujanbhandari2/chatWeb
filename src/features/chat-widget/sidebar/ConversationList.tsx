import type { RefObject } from 'react';
import type { Conversation } from '../../../types/chat';
import type { WidgetFeatures } from '../../../schemas/widget.schemas';
import { AvatarWithPresence } from '../../chat/chat-ui';
import { isGlobalConversation, userInitials } from '../../../utils/chat.utils';

export type ConversationListProps = {
  conversations: Conversation[];
  allConversations: Conversation[];
  searchQuery: string;
  onSearchChange: (query: string) => void;
  selectedConversationId: string | null;
  onSelectConversation: (id: string) => void;
  unreadByConversation: Record<string, number>;
  getSingleOtherParticipantId: (conversation: Conversation) => string | undefined;
  getConversationTitle: (conversation: Conversation) => string;
  getConversationSubtitle: (conversation: Conversation) => string;
  isPeerOnline: (userId: string) => boolean;
  menuOpen: boolean;
  onMenuToggle: (open: boolean) => void;
  overflowMenuRef: RefObject<HTMLDivElement>;
  onNavigateToPeople: () => void;
  onNavigateToNewGroup: () => void;
  features: WidgetFeatures;
};

/**
 * Main chat list: search, overflow menu, conversation rows, empty states.
 */
export function ConversationList({
  conversations,
  allConversations,
  searchQuery,
  onSearchChange,
  selectedConversationId,
  onSelectConversation,
  unreadByConversation,
  getSingleOtherParticipantId,
  getConversationTitle,
  getConversationSubtitle,
  isPeerOnline,
  menuOpen,
  onMenuToggle,
  overflowMenuRef,
  onNavigateToPeople,
  onNavigateToNewGroup,
  features,
}: ConversationListProps): JSX.Element {
  const hasNoConversations = allConversations.length === 0;
  const hasNoSearchResults = allConversations.length > 0 && conversations.length === 0;

  return (
    <section className="conversation-list" aria-label="Your conversations">
      <ConversationListHeader
        searchQuery={searchQuery}
        onSearchChange={onSearchChange}
        menuOpen={menuOpen}
        onMenuToggle={onMenuToggle}
        overflowMenuRef={overflowMenuRef}
        onNavigateToPeople={onNavigateToPeople}
        onNavigateToNewGroup={onNavigateToNewGroup}
        features={features}
      />

      <div>
        {conversations.map((conversation) => (
          <ConversationListItem
            key={conversation.id}
            conversation={conversation}
            isSelected={conversation.id === selectedConversationId}
            unreadCount={unreadByConversation[conversation.id] ?? 0}
            otherParticipantId={getSingleOtherParticipantId(conversation)}
            title={getConversationTitle(conversation)}
            subtitle={getConversationSubtitle(conversation)}
            isPeerOnline={isPeerOnline}
            onSelect={() => void onSelectConversation(conversation.id)}
          />
        ))}
      </div>

      {hasNoSearchResults && (
        <p className="muted-text widget-chats-empty-hint">No chats match your search.</p>
      )}

      {hasNoConversations && (
        <p className="muted-text widget-chats-empty-hint">
          No chats yet. Tap ⋮ and choose Suggested people to browse everyone.
        </p>
      )}
    </section>
  );
}

type ConversationListHeaderProps = {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  menuOpen: boolean;
  onMenuToggle: (open: boolean) => void;
  overflowMenuRef: RefObject<HTMLDivElement>;
  onNavigateToPeople: () => void;
  onNavigateToNewGroup: () => void;
  features: WidgetFeatures;
};

function ConversationListHeader({
  searchQuery,
  onSearchChange,
  menuOpen,
  onMenuToggle,
  overflowMenuRef,
  onNavigateToPeople,
  onNavigateToNewGroup,
  features,
}: ConversationListHeaderProps): JSX.Element {
  return (
    <div className="widget-chats-search-row">
      <div className="widget-chats-menu-wrap" ref={overflowMenuRef}>
        <button
          type="button"
          className="chat-header-menu-btn widget-chats-overflow-btn"
          aria-expanded={menuOpen}
          aria-haspopup="menu"
          aria-label="More options"
          onClick={() => onMenuToggle(!menuOpen)}
        >
          ⋮
        </button>

        {menuOpen && (
          <div className="rail-menu-dropdown rail-menu-dropdown--widget-chats-row" role="menu">
            <button
              type="button"
              role="menuitem"
              className="rail-menu-item rail-menu-item--widget-suggest"
              onClick={onNavigateToPeople}
            >
              Suggested people
            </button>

            {features.createGroup && (
              <button
                type="button"
                role="menuitem"
                className="rail-menu-item rail-menu-item--widget-suggest"
                onClick={onNavigateToNewGroup}
              >
                New group
              </button>
            )}
          </div>
        )}
      </div>

      {features.chatListSearch && (
        <label className="widget-chats-search-label">
          <span className="visually-hidden">Search your chats</span>
          <input
            className="quick-chat-search widget-chats-search-input"
            type="search"
            value={searchQuery}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="Search chats…"
            autoComplete="off"
            spellCheck={false}
            aria-label="Search chats"
          />
        </label>
      )}
    </div>
  );
}

type ConversationListItemProps = {
  conversation: Conversation;
  isSelected: boolean;
  unreadCount: number;
  otherParticipantId: string | undefined;
  title: string;
  subtitle: string;
  isPeerOnline: (userId: string) => boolean;
  onSelect: () => void;
};

function ConversationListItem({
  conversation,
  isSelected,
  unreadCount,
  otherParticipantId,
  title,
  subtitle,
  isPeerOnline,
  onSelect,
}: ConversationListItemProps): JSX.Element {
  const hasUnread = unreadCount > 0;
  const otherUserIsOnline =
    otherParticipantId !== undefined &&
    !isGlobalConversation(conversation) &&
    isPeerOnline(otherParticipantId);

  const avatar = (
    <div className="avatar-mini">
      {isGlobalConversation(conversation)
        ? 'ALL'
        : userInitials(conversation.participants[0]?.user ?? { name: null, email: '?' })}
    </div>
  );

  const ariaLabel =
    hasUnread ? `${title}, ${unreadCount} unread message${unreadCount === 1 ? '' : 's'}` : title;

  return (
    <button
      type="button"
      className={`conversation-item${isSelected ? ' active' : ''}${
        hasUnread ? ' conversation-item--unread' : ''
      }`}
      aria-label={ariaLabel}
      aria-current={isSelected ? 'true' : undefined}
      onClick={onSelect}
    >
      {otherParticipantId !== undefined && !isGlobalConversation(conversation) ? (
        <AvatarWithPresence online={otherUserIsOnline}>{avatar}</AvatarWithPresence>
      ) : (
        avatar
      )}

      <div className="conversation-meta">
        <div className="conversation-meta-top">
          <strong>{title}</strong>
          {hasUnread && (
            <span className="unread-badge" aria-hidden="true">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </div>
        <span>{subtitle}</span>
      </div>
    </button>
  );
}
