import { DeepPartialWidgetConfig } from "../../schemas/widget.schemas";

export const prodSandboxPartial: DeepPartialWidgetConfig = {
    features: {
      imageUpload: true,
      audioAttachmentUpload: true,
      voiceRecording: false,
      createGroup: false,
      editGroup: false,
      chatListSearch: true,
      translateMessages: false,
      voiceTranscription: false,
      messageReactions: true,
      deleteConversation: false,
      deleteMessage: false,
    },
    uiElements: {
      panelTitle: 'VSuite Chat',
    },
  };