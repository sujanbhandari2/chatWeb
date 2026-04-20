import { userDisplayName } from '../../../utils/chat.utils';
import { useEditGroupFormState } from '../../../hooks/useEditGroupFormState';

/** Add-members flow aligned with Vitafy `POST …/conversations/:id/participants` (no rename/remove/leave in API). */
export function EditGroupForm(): JSX.Element {
  const {
    editGroupFormId,
    user,
    editGroupTitle,
    editGroupParticipantIds,
    editGroupPickerSearch,
    setEditGroupPickerSearch,
    editGroupError,
    editGroupSaving,
    handleSaveEditGroup,
    addEditGroupMember,
    filteredEditGroupPickerPeers,
    displayNameForParticipantId,
    exitEditGroupRailToChats
  } = useEditGroupFormState();

  const onCancel = (): void => {
    exitEditGroupRailToChats();
  };

  const displayTitle = editGroupTitle.trim() || 'Group chat';

  return (
    <>
      <div className="widget-new-group-scroll">
        <form
          id={editGroupFormId}
          className="group-modal-form widget-new-group-form"
          onSubmit={(event) => void handleSaveEditGroup(event)}
        >
          <div className="modal-field">
            <span className="modal-label">Group</span>
            <p className="modal-input" style={{ margin: 0, fontWeight: 600 }}>
              {displayTitle}
            </p>
            <span className="muted-text" style={{ display: 'block', marginTop: 6 }}>
              Name is not updated on the server. You can only add members below.
            </span>
          </div>

          <div className="modal-field">
            <span className="modal-label">Members ({editGroupParticipantIds.length})</span>
            <div className="group-member-chips">
              {editGroupParticipantIds.map((id) => (
                <span key={id} className={`group-member-chip ${id === user?.id ? 'group-member-chip--self' : ''}`}>
                  <span>
                    {displayNameForParticipantId(id)}
                    {id === user?.id ? ' (you)' : ''}
                  </span>
                </span>
              ))}
            </div>
          </div>

          <label className="modal-field">
            <span className="modal-label">Add people</span>
            <input
              className="modal-input"
              type="search"
              value={editGroupPickerSearch}
              onChange={(event) => setEditGroupPickerSearch(event.target.value)}
              placeholder="Search by name or email…"
              autoComplete="off"
            />
          </label>

          <div className="group-picker-list" role="list">
            {filteredEditGroupPickerPeers.length === 0 ? (
              <p className="muted-text">No one left to add, or no matches.</p>
            ) : (
              filteredEditGroupPickerPeers.map((peer) => (
                <div key={peer.id} className="group-picker-row" role="listitem">
                  <div className="group-picker-meta">
                    <strong>{userDisplayName(peer)}</strong>
                    <span className="group-picker-email">{peer.email}</span>
                  </div>
                  <button
                    type="button"
                    className="group-picker-add"
                    onClick={() => addEditGroupMember(peer.id)}
                    disabled={editGroupSaving}
                  >
                    Add
                  </button>
                </div>
              ))
            )}
          </div>

          {editGroupError && <p className="modal-error">{editGroupError}</p>}
        </form>
      </div>
      <div className="widget-new-group-footer">
        <button type="button" className="modal-btn modal-btn-secondary" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="submit"
          form={editGroupFormId}
          className="modal-btn modal-btn-primary"
          disabled={editGroupSaving}
        >
          {editGroupSaving ? 'Saving…' : 'Add members'}
        </button>
      </div>
    </>
  );
}
