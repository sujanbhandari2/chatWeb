import type { TenantUser } from '../../../types/chat';
import { AvatarWithPresence } from '../../chat/chat-ui';
import { userDisplayName, userInitials } from '../../../utils/chat.utils';

export type PeopleDirectoryProps = {
  sortedPeers: TenantUser[];
  filteredPeople: TenantUser[];
  searchQuery: string;
  onSearchChange: (query: string) => void;
  openingUserId: string | null;
  onOpenChat: (user: TenantUser) => void;
};

/** Searchable tenant people list for opening DMs. */
export function PeopleDirectory({
  sortedPeers,
  filteredPeople,
  searchQuery,
  onSearchChange,
  openingUserId,
  onOpenChat,
}: PeopleDirectoryProps): JSX.Element {
  const hasNoPeers = sortedPeers.length === 0;
  const hasNoResults = sortedPeers.length > 0 && filteredPeople.length === 0;

  return (
    <section className="quick-chat" aria-label="All people in your tenant">
      <label className="quick-chat-search-label">
        <span className="visually-hidden">Search people by name or email</span>
        <input
          className="quick-chat-search"
          type="search"
          value={searchQuery}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder="Search people…"
          autoComplete="off"
          spellCheck={false}
          aria-label="Search all people"
        />
      </label>

      <div className="quick-list">
        {hasNoPeers && <span className="muted-text">No other users in this tenant yet.</span>}

        {hasNoResults && (
          <span className="muted-text">No one matches &quot;{searchQuery.trim()}&quot;.</span>
        )}

        {filteredPeople.map((person) => (
          <PersonListItem
            key={person.id}
            person={person}
            isOpening={openingUserId === person.id}
            onOpenChat={onOpenChat}
          />
        ))}
      </div>
    </section>
  );
}

type PersonListItemProps = {
  person: TenantUser;
  isOpening: boolean;
  onOpenChat: (user: TenantUser) => void;
};

function PersonListItem({ person, isOpening, onOpenChat }: PersonListItemProps): JSX.Element {
  const displayName = userDisplayName(person);

  return (
    <button
      type="button"
      className="quick-item"
      onClick={() => void onOpenChat(person)}
      disabled={isOpening}
      aria-label={`Open chat with ${displayName}`}
    >
      <AvatarWithPresence online={person.isOnline}>
        <div className="avatar-mini">{userInitials(person)}</div>
      </AvatarWithPresence>

      <div className="quick-user-meta">
        <strong>{displayName}</strong>
        <span>
          {person.status ?? '—'} · {person.isOnline ? 'Active' : 'Away'}
        </span>
        <span className="quick-user-email">{person.email}</span>
      </div>

      <span className="quick-item-action">{isOpening ? 'Opening…' : 'Chat →'}</span>
    </button>
  );
}
