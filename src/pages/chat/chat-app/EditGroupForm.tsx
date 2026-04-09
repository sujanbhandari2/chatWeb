import { userDisplayName } from '../../../utils/chat.utils';
import { useAuthStore } from '../../../store/useAuthStore';
import { useChatSelectors } from '../../../hooks/useChatSelectors';
import { useDisplayNameForParticipant, useFilteredEditGroupPickerPeers } from '../../../hooks/useChatDerived';
import { useChatRuntimeContext } from '../../../hooks/ChatRuntimeContext';
import { WidgetPanelType } from '../../../types/chat';

export function EditGroupForm(): JSX.Element {
  const { editGroupFormId } = useChatRuntimeContext();
  const user = useAuthStore((s) => s.user);
  const {
    editGroupTitle,
    setEditGroupTitle,
    editGroupParticipantIds,
    editGroupPickerSearch,
    setEditGroupPickerSearch,
    editGroupError,
    editGroupSaving,
    handleSaveEditGroup,
    handleLeaveGroup,
    setWidgetRailPane,
    setEditGroupError,
    addEditGroupMember,
    removeEditGroupMember,
  } = useChatSelectors((s) => ({
    editGroupTitle: s.editGroupTitle,
    setEditGroupTitle: s.setEditGroupTitle,
    editGroupParticipantIds: s.editGroupParticipantIds,
    editGroupPickerSearch: s.editGroupPickerSearch,
    setEditGroupPickerSearch: s.setEditGroupPickerSearch,
    editGroupError: s.editGroupError,
    editGroupSaving: s.editGroupSaving,
    handleSaveEditGroup: s.handleSaveEditGroup,
    handleLeaveGroup: s.handleLeaveGroup,
    setWidgetRailPane: s.setWidgetRailPane,
    setEditGroupError: s.setEditGroupError,
    addEditGroupMember: s.addEditGroupMember,
    removeEditGroupMember: s.removeEditGroupMember,
  }));
  const filteredEditGroupPickerPeers = useFilteredEditGroupPickerPeers();
  const displayNameForParticipantId = useDisplayNameForParticipant();

  const onCancel = (): void => {
    if (editGroupSaving) {
      return;
    }
    setWidgetRailPane(WidgetPanelType.CHATS);
    setEditGroupError('');
  };

  const formFields = (
    <>
      <label className="modal-field">
        <span className="modal-label">Group name</span>
        <input
          className="modal-input"
          value={editGroupTitle}
          onChange={(event) => setEditGroupTitle(event.target.value)}
          maxLength={120}
          required
        />
      </label>

      <div className="modal-field">
        <span className="modal-label">Members ({editGroupParticipantIds.length})</span>
        <div className="group-member-chips">
          {editGroupParticipantIds.map((id) => (
            <span key={id} className={`group-member-chip ${id === user?.id ? 'group-member-chip--self' : ''}`}>
              <span>
                {displayNameForParticipantId(id)}
                {id === user?.id ? ' (you)' : ''}
              </span>
              {id !== user?.id && (
                <button
                  type="button"
                  className="group-member-chip-remove"
                  onClick={() => removeEditGroupMember(id)}
                  disabled={editGroupSaving || editGroupParticipantIds.length <= 2}
                  aria-label={`Remove ${displayNameForParticipantId(id)}`}
                >
                  ×
                </button>
              )}
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

      <div className="modal-leave-row">
        <button
          type="button"
          className="modal-btn modal-btn-leave"
          disabled={editGroupSaving}
          onClick={() => void handleLeaveGroup()}
        >
          Leave group
        </button>
      </div>
    </>
  );

  return (
    <>
      <div className="widget-new-group-scroll">
        <form
          id={editGroupFormId}
          className="group-modal-form widget-new-group-form"
          onSubmit={(event) => void handleSaveEditGroup(event)}
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
          form={editGroupFormId}
          className="modal-btn modal-btn-primary"
          disabled={editGroupSaving}
        >
          {editGroupSaving ? 'Saving…' : 'Save changes'}
        </button>
      </div>
    </>
  );
}
