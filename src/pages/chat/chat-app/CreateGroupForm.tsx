import { userDisplayName } from '../../../utils/chat.utils';
import { useChatSelectors } from '../../../hooks/useChatSelectors';
import { useFilteredGroupPickerPeers, useSortedTenantPeers, useUsersById } from '../../../hooks/useChatDerived';
import { useChatRuntimeContext } from '../../../hooks/ChatRuntimeContext';
import { WidgetPanelType } from '../../../types/chat';

export function CreateGroupForm(): JSX.Element {
  const { newGroupFormId } = useChatRuntimeContext();
  const {
    groupTitle,
    setGroupTitle,
    groupSelectedUserIds,
    groupPickerSearch,
    setGroupPickerSearch,
    groupModalError,
    setGroupModalError,
    creatingGroup,
    handleCreateGroup,
    setWidgetRailPane,
    addUserToGroupSelection,
    removeUserFromGroupSelection,
  } = useChatSelectors((s) => ({
    groupTitle: s.groupTitle,
    setGroupTitle: s.setGroupTitle,
    groupSelectedUserIds: s.groupSelectedUserIds,
    groupPickerSearch: s.groupPickerSearch,
    setGroupPickerSearch: s.setGroupPickerSearch,
    groupModalError: s.groupModalError,
    setGroupModalError: s.setGroupModalError,
    creatingGroup: s.creatingGroup,
    handleCreateGroup: s.handleCreateGroup,
    setWidgetRailPane: s.setWidgetRailPane,
    addUserToGroupSelection: s.addUserToGroupSelection,
    removeUserFromGroupSelection: s.removeUserFromGroupSelection,
  }));
  const sortedTenantPeers = useSortedTenantPeers();
  const filteredGroupPickerPeers = useFilteredGroupPickerPeers();
  const usersById = useUsersById();

  const onCancel = (): void => {
    if (creatingGroup) {
      return;
    }
    setWidgetRailPane(WidgetPanelType.CHATS);
    setGroupModalError('');
  };

  const formFields = (
    <>
      <label className="modal-field">
        <span className="modal-label">Group name</span>
        <input
          className="modal-input"
          value={groupTitle}
          onChange={(event) => setGroupTitle(event.target.value)}
          placeholder="e.g. Care team"
          maxLength={120}
          required
        />
      </label>

      <div className="modal-field">
        <span className="modal-label">Members ({groupSelectedUserIds.length} selected)</span>
        <div className="group-member-chips">
          {groupSelectedUserIds.length === 0 && (
            <span className="muted-text">No members yet — add from the list below.</span>
          )}
          {groupSelectedUserIds.map((id) => {
            const peer = usersById.get(id);
            if (!peer) {
              return null;
            }
            return (
              <span key={id} className="group-member-chip">
                <span>{userDisplayName(peer)}</span>
                <button
                  type="button"
                  className="group-member-chip-remove"
                  onClick={() => removeUserFromGroupSelection(id)}
                  disabled={creatingGroup}
                  aria-label={`Remove ${userDisplayName(peer)}`}
                >
                  ×
                </button>
              </span>
            );
          })}
        </div>
      </div>

      <label className="modal-field">
        <span className="modal-label">Add people</span>
        <input
          className="modal-input"
          type="search"
          value={groupPickerSearch}
          onChange={(event) => setGroupPickerSearch(event.target.value)}
          placeholder="Search by name or email…"
          autoComplete="off"
        />
      </label>

      <div className="group-picker-list" role="list">
        {sortedTenantPeers.length === 0 ? (
          <p className="muted-text">No other users in your tenant.</p>
        ) : filteredGroupPickerPeers.length === 0 ? (
          <p className="muted-text">Everyone matching your search is already added.</p>
        ) : (
          filteredGroupPickerPeers.map((peer) => (
            <div key={peer.id} className="group-picker-row" role="listitem">
              <div className="group-picker-meta">
                <strong>{userDisplayName(peer)}</strong>
                <span className="group-picker-email">{peer.email}</span>
              </div>
              <button
                type="button"
                className="group-picker-add"
                onClick={() => addUserToGroupSelection(peer.id)}
                disabled={creatingGroup}
              >
                Add
              </button>
            </div>
          ))
        )}
      </div>

      {groupModalError && <p className="modal-error">{groupModalError}</p>}
    </>
  );

  return (
    <>
      <div className="widget-new-group-scroll">
        <form
          id={newGroupFormId}
          className="group-modal-form widget-new-group-form"
          onSubmit={(event) => void handleCreateGroup(event)}
        >
          {formFields}
        </form>
      </div>
      <div className="widget-new-group-footer">
        <button type="button" className="modal-btn modal-btn-secondary" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="submit"
          form={newGroupFormId}
          className="modal-btn modal-btn-primary"
          disabled={creatingGroup}
        >
          {creatingGroup ? 'Creating…' : 'Create group'}
        </button>
      </div>
    </>
  );
}
