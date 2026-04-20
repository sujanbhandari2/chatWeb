import { DeepPartialWidgetConfig } from "../../schemas/widget.schemas";

export const devSandboxPartial: DeepPartialWidgetConfig = {
    features: {
      imageUpload: true,
      audioAttachmentUpload: true,
      voiceRecording: true,
      createGroup: true,
      editGroup: true,
      chatListSearch: true,
      translateMessages: true,
      voiceTranscription: true,
      messageReactions: true,
      deleteConversation: true,
    },
    uiElements: {
      panelTitle: 'VSuite Chat',
    },
    interactions: {
      defaultOpen: true
    }
  };