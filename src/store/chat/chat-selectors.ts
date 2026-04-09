import type { ChatStore } from './chatStore.types';

/** Widget shell: rail + selection (header / overlay / runtime chrome). */
export const selectWidgetChrome = (s: ChatStore) => ({
  widgetRailPane: s.widgetRailPane,
  selectedConversationId: s.selectedConversationId,
});

/** `useChatRuntime` effects subscription slice. */
export const selectRuntimeSubscriptionSlice = (s: ChatStore) => ({
  selectedConversationId: s.selectedConversationId,
  messages: s.messages,
  messageActionsMenuId: s.messageActionsMenuId,
  isRecording: s.isRecording,
  widgetRailPane: s.widgetRailPane,
  creatingGroup: s.creatingGroup,
  editGroupSaving: s.editGroupSaving,
  chatHeaderMenuOpen: s.chatHeaderMenuOpen,
  widgetInboxMenuOpen: s.widgetInboxMenuOpen,
  conversations: s.conversations,
});

/** Main thread stage: messages, composer, header menus, handlers. */
export const selectThreadView = (s: ChatStore) => ({
  selectedConversationId: s.selectedConversationId,
  widgetRailPane: s.widgetRailPane,
  messages: s.messages,
  text: s.text,
  setText: s.setText,
  error: s.error,
  chatHeaderMenuOpen: s.chatHeaderMenuOpen,
  setChatHeaderMenuOpen: s.setChatHeaderMenuOpen,
  messageActionsMenuId: s.messageActionsMenuId,
  setMessageActionsMenuId: s.setMessageActionsMenuId,
  messageSpeechUi: s.messageSpeechUi,
  patchMessageSpeechUi: s.patchMessageSpeechUi,
  widgetBackToInbox: s.widgetBackToInbox,
  openEditGroupModal: s.openEditGroupModal,
  handleDeleteSelectedConversation: s.handleDeleteSelectedConversation,
  deletingConversation: s.deletingConversation,
  handleSendText: s.handleSendText,
  handleReact: s.handleReact,
  handleMarkRead: s.handleMarkRead,
  handleDelete: s.handleDelete,
  handleTranscribeVoiceMessage: s.handleTranscribeVoiceMessage,
  handleTranslateForMessage: s.handleTranslateForMessage,
  isRecording: s.isRecording,
  recordingDurationMs: s.recordingDurationMs,
});

/** Sidebar rails: people, inbox, group flows (Zustand fields only). */
export const selectSidebarRails = (s: ChatStore) => ({
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
  exitNewGroupRailToChats: s.exitNewGroupRailToChats,
  exitEditGroupRailToChats: s.exitEditGroupRailToChats,
});

export const selectCreateGroupForm = (s: ChatStore) => ({
  groupTitle: s.groupTitle,
  setGroupTitle: s.setGroupTitle,
  groupSelectedUserIds: s.groupSelectedUserIds,
  groupPickerSearch: s.groupPickerSearch,
  setGroupPickerSearch: s.setGroupPickerSearch,
  groupModalError: s.groupModalError,
  setGroupModalError: s.setGroupModalError,
  creatingGroup: s.creatingGroup,
  handleCreateGroup: s.handleCreateGroup,
  addUserToGroupSelection: s.addUserToGroupSelection,
  removeUserFromGroupSelection: s.removeUserFromGroupSelection,
  exitNewGroupRailToChats: s.exitNewGroupRailToChats,
});

export const selectEditGroupForm = (s: ChatStore) => ({
  editGroupTitle: s.editGroupTitle,
  setEditGroupTitle: s.setEditGroupTitle,
  editGroupParticipantIds: s.editGroupParticipantIds,
  editGroupPickerSearch: s.editGroupPickerSearch,
  setEditGroupPickerSearch: s.setEditGroupPickerSearch,
  editGroupError: s.editGroupError,
  editGroupSaving: s.editGroupSaving,
  handleSaveEditGroup: s.handleSaveEditGroup,
  handleLeaveGroup: s.handleLeaveGroup,
  setEditGroupError: s.setEditGroupError,
  addEditGroupMember: s.addEditGroupMember,
  removeEditGroupMember: s.removeEditGroupMember,
  exitEditGroupRailToChats: s.exitEditGroupRailToChats,
});
