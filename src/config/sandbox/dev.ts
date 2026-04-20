import { DeepPartialWidgetConfig } from "../../schemas/widget.schemas";

export const devSandboxPartial: DeepPartialWidgetConfig = {
    features: {
      imageUpload: true,
      audioAttachmentUpload: true,
      voiceRecording: false,
      createGroup: true,
      editGroup: true,
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