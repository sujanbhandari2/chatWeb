import type { FormEvent } from 'react';
import type {
  Conversation,
  DeliveredReceipt,
  Message,
  MessageReaction,
  MessageType,
  ReadReceipt,
  TenantUser,
  WidgetPanelType
} from '../../types/chat';

/** @deprecated Use `WidgetPanelType` from `types/chat`. */
export type WidgetRailPane = WidgetPanelType;

export type MessageSpeechUiState = {
  transcript?: string;
  translated?: string;
  targetLang?: string;
  loading?: 'transcribe' | 'translate';
  error?: string;
  translateToolsOpen?: boolean;
};

export const chatInitialState = {
  conversations: [] as Conversation[],
  tenantUsers: [] as TenantUser[],
  selectedConversationId: '',
  messages: [] as Message[],
  text: '',
  error: '',
  openingDirectUserId: '',
  peopleSearchQuery: '',
  groupTitle: '',
  groupSelectedUserIds: [] as string[],
  groupPickerSearch: '',
  creatingGroup: false,
  groupModalError: '',
  chatHeaderMenuOpen: false,
  messageActionsMenuId: null as string | null,
  editGroupTitle: '',
  editGroupParticipantIds: [] as string[],
  editGroupInitialParticipantIds: [] as string[],
  editGroupConversationId: '',
  editGroupPickerSearch: '',
  editGroupSaving: false,
  editGroupError: '',
  deletingConversation: false,
  isRecording: false,
  socketConnected: false,
  unreadByConversation: {} as Record<string, number>,
  widgetRailPane: 'chats' as WidgetPanelType,
  widgetChatSearchQuery: '',
  widgetInboxMenuOpen: false,
  recordingDurationMs: 0,
  messageSpeechUi: {} as Record<string, MessageSpeechUiState>,
  /** Other participants currently typing in the selected thread (from `user_typing`). */
  remoteTypingUserIds: [] as string[]
};

export type ChatState = typeof chatInitialState;

export type ChatActions = {
  reset: () => void;
  setConversations: (v: Conversation[] | ((p: Conversation[]) => Conversation[])) => void;
  setTenantUsers: (v: TenantUser[] | ((p: TenantUser[]) => TenantUser[])) => void;
  setSelectedConversationId: (id: string) => void;
  setMessages: (v: Message[] | ((p: Message[]) => Message[])) => void;
  setText: (t: string) => void;
  setError: (e: string) => void;
  setOpeningDirectUserId: (id: string) => void;
  setPeopleSearchQuery: (q: string) => void;
  setGroupTitle: (t: string) => void;
  setGroupSelectedUserIds: (v: string[] | ((p: string[]) => string[])) => void;
  setGroupPickerSearch: (q: string) => void;
  setCreatingGroup: (v: boolean) => void;
  setGroupModalError: (e: string) => void;
  setChatHeaderMenuOpen: (v: boolean | ((o: boolean) => boolean)) => void;
  setMessageActionsMenuId: (id: string | null | ((c: string | null) => string | null)) => void;
  setEditGroupTitle: (t: string) => void;
  setEditGroupParticipantIds: (v: string[] | ((p: string[]) => string[])) => void;
  setEditGroupConversationId: (id: string) => void;
  setEditGroupPickerSearch: (q: string) => void;
  setEditGroupSaving: (v: boolean) => void;
  setEditGroupError: (e: string) => void;
  setDeletingConversation: (v: boolean) => void;
  setIsRecording: (v: boolean) => void;
  setSocketConnected: (v: boolean) => void;
  setUnreadByConversation: (v: Record<string, number> | ((p: Record<string, number>) => Record<string, number>)) => void;
  setWidgetRailPane: (p: WidgetPanelType) => void;
  setWidgetChatSearchQuery: (q: string) => void;
  setWidgetInboxMenuOpen: (v: boolean | ((o: boolean) => boolean)) => void;
  setRecordingDurationMs: (ms: number) => void;
  patchMessageSpeechUi: (messageId: string, patch: Partial<MessageSpeechUiState>) => void;
  upsertMessage: (incoming: Message) => void;
  bumpConversationUpdatedAt: (conversationId: string, iso: string) => void;
  updateTenantUserOnline: (userId: string, isOnline: boolean) => void;
  applyTenantPresenceMap: (map: Record<string, boolean>) => void;
  setAllTenantOnlineFromIds: (ids: string[]) => void;
  clearMessageSpeechOnConversationChange: () => void;
  widgetBackToInbox: () => void;
  openGroupModal: () => void;
  /** Leave new-group rail to chats (no-op while `creatingGroup`). */
  exitNewGroupRailToChats: () => void;
  /** Leave edit-group rail to chats (no-op while `editGroupSaving`). */
  exitEditGroupRailToChats: () => void;
  addUserToGroupSelection: (userId: string) => void;
  removeUserFromGroupSelection: (userId: string) => void;
  addEditGroupMember: (userId: string) => void;
  removeEditGroupMember: (userId: string) => void;
  openEditGroupModal: () => void;
  applyReactionFromSocket: (
    reaction: MessageReaction & { conversationId?: string; reactionType?: string }
  ) => void;
  applyMessageDeleted: (payload: { messageId: string; conversationId: string; deletedAt: string }) => void;
  applyDeliveredReceipt: (receipt: DeliveredReceipt & { conversationId?: string }) => void;
  applyReadReceipt: (receipt: ReadReceipt & { conversationId?: string }) => void;
  clearRemoteTypingPeers: () => void;
  applyRemoteTypingStart: (conversationId: string, userId: string, currentUserId: string | undefined) => void;
  applyRemoteTypingStop: (conversationId: string, userId: string) => void;
  handleLogout: () => void;
  selectConversation: (conversationId: string) => Promise<void>;
  refreshConversations: () => Promise<Conversation[]>;
  refreshUsers: () => Promise<void>;
  bootstrapChatApp: () => Promise<void>;
  openDirectChat: (target: TenantUser) => Promise<void>;
  handleCreateGroup: (event: FormEvent) => Promise<void>;
  handleSaveEditGroup: (event: FormEvent) => Promise<void>;
  handleLeaveGroup: () => Promise<void>;
  handleDeleteSelectedConversation: () => Promise<void>;
  handleSendText: () => Promise<void>;
  handleSendUploadedMessage: (file: File, type: MessageType) => Promise<void>;
  handleReact: (messageId: string, emoji: string) => void;
  handleDelete: (messageId: string) => Promise<void>;
  handleMarkRead: (messageId: string) => Promise<void>;
  handleTranscribeVoiceMessage: (message: Message) => Promise<void>;
  handleTranslateForMessage: (message: Message, sourceText: string, targetLanguage: string) => Promise<void>;
};

export type ChatStore = ChatState & ChatActions;
