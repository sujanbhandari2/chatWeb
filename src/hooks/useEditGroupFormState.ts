import { useAuthStore } from '../store/useAuthStore';
import { useChatSelectors } from './useChatSelectors';
import { useDisplayNameForParticipant, useFilteredEditGroupPickerPeers } from './useChatDerived';
import { useChatRuntimeContext } from './ChatRuntimeContext';
import { selectEditGroupForm } from '../store/chat/chat-selectors';

/** Edit-group rail: store slice + picker data + form id. */
export function useEditGroupFormState() {
  const { editGroupFormId } = useChatRuntimeContext();
  const user = useAuthStore((s) => s.user);
  const slice = useChatSelectors(selectEditGroupForm);
  const filteredEditGroupPickerPeers = useFilteredEditGroupPickerPeers();
  const displayNameForParticipantId = useDisplayNameForParticipant();

  return {
    ...slice,
    editGroupFormId,
    user,
    filteredEditGroupPickerPeers,
    displayNameForParticipantId,
  };
}
