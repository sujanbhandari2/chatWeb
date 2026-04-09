import { useChatSelectors } from './useChatSelectors';
import { useFilteredGroupPickerPeers, useSortedTenantPeers, useUsersById } from './useChatDerived';
import { useChatRuntimeContext } from './ChatRuntimeContext';
import { selectCreateGroupForm } from '../store/chat/chat-selectors';

/** New-group rail: store slice + picker data + form id. */
export function useCreateGroupFormState() {
  const { newGroupFormId } = useChatRuntimeContext();
  const slice = useChatSelectors(selectCreateGroupForm);
  const sortedTenantPeers = useSortedTenantPeers();
  const filteredGroupPickerPeers = useFilteredGroupPickerPeers();
  const usersById = useUsersById();

  return {
    ...slice,
    newGroupFormId,
    sortedTenantPeers,
    filteredGroupPickerPeers,
    usersById,
  };
}
