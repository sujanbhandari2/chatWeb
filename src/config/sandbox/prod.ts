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
      voiceTranscription: true,
      messageReactions: false,
      deleteConversation: true,
    },
    uiElements: {
      panelTitle: 'VSuite Chat',
    },
  };