import type { RefObject } from 'react';

/** Socket.IO lifecycle for the embed widget status strip. */
export type WidgetSocketConnectionStatus =
  | 'inactive'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'disconnected'
  | 'error';

export type WidgetSocketConnection = {
  status: WidgetSocketConnectionStatus;
  /** Last disconnect reason or connect_error message (for `title` / debugging). */
  detail?: string;
};

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
  socketConnection: WidgetSocketConnection;
};
