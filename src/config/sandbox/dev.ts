import { DeepPartialWidgetConfig } from "../../schemas/widget.schemas";

export const devSandboxPartial: DeepPartialWidgetConfig = {
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