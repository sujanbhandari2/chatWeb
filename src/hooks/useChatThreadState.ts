import { useAuthStore } from '../store/useAuthStore';
import { useChatSelectors } from './useChatSelectors';
import {
  useConversationSubtitleGetter,
  useConversationTitleGetter,
  useSelectedConversation,
  useSelectedDirectPeerId,
  useTenantUserOnlineLookup,
  useUsersById
} from './useChatDerived';
import { useChatRuntimeContext } from './ChatRuntimeContext';
import { useWidgetFeatures } from './useWidgetInitConfig';
import { selectThreadView } from '../store/chat/chat-selectors';

/** Thread stage: Zustand thread slice + derived conversation/presence + runtime refs. */
export function useChatThreadState() {
  const features = useWidgetFeatures();
  const user = useAuthStore((s) => s.user);
  const threadSlice = useChatSelectors(selectThreadView);
  const selectedConversation = useSelectedConversation();
  const selectedDirectPeerId = useSelectedDirectPeerId();
  const getConversationTitle = useConversationTitleGetter();
  const getConversationSubtitle = useConversationSubtitleGetter();
  const isPeerOnline = useTenantUserOnlineLookup();
  const usersById = useUsersById();
  const {
    messageScrollerRef,
    chatHeaderMenuRef,
    startRecording,
    finishRecording,
    cancelRecording
  } = useChatRuntimeContext();

  return {
    features,
    user,
    ...threadSlice,
    selectedConversation,
    selectedDirectPeerId,
    getConversationTitle,
    getConversationSubtitle,
    isPeerOnline,
    usersById,
    messageScrollerRef,
    chatHeaderMenuRef,
    startRecording,
    finishRecording,
    cancelRecording,
  };
}
