import type { RefObject } from 'react';

/** Refs and recording controls shared by chat UI (sidebar, thread, group forms). */
export type ChatRuntimeValue = {
  messageScrollerRef: RefObject<HTMLElement | null>;
  chatHeaderMenuRef: RefObject<HTMLDivElement | null>;
  /** ⋮ overflow next to the conversation list search */
  chatsListOverflowMenuRef: RefObject<HTMLDivElement | null>;
  newGroupFormId: string;
  editGroupFormId: string;
  startRecording: () => Promise<void>;
  finishRecording: () => void;
  cancelRecording: () => void;
  /** Debounced `typing_start` / `typing_stop` for the active thread. */
  notifyComposerTyping: () => void;
};
