import type { ReactNode } from 'react';
import type { WidgetInitConfig } from '../schemas/widget.schemas';
import type { AuthUser, WidgetPanelType } from './chat';
import type { ChatRuntimeValue } from './chat-runtime.types';

export interface WidgetChatAppProps {
  widgetConfig?: WidgetInitConfig;
}

/** Output of `useWidgetConfig` — embed-ready config + auth + runtime + rail UI. */
export type WidgetConfigState = {
  config: WidgetInitConfig;
  runtime: ChatRuntimeValue;
  token: string;
  user: AuthUser | null;
  sessionHydrated: boolean;
  currentPanel: WidgetPanelType;
  selectedConversationId: string;
  isMissingTenant: boolean;
  headerLabel: string;
  overlayVisible: boolean;
};

export type WidgetSessionLoadingShellProps = {
  config: WidgetInitConfig;
};

export type WidgetUnauthenticatedShellProps = {
  config: WidgetInitConfig;
  isMissingTenant: boolean;
};

export type WidgetUnauthorizedReason = 'missingApiKey';

export type WidgetUnauthorizedShellProps = {
  config: WidgetInitConfig;
  reason?: WidgetUnauthorizedReason;
};

export type WidgetAuthenticatedLayoutProps = {
  config: WidgetInitConfig;
  runtime: ChatRuntimeValue;
  headerLabel: string;
  overlayVisible: boolean;
  selectedConversationId: string;
  currentPanel: WidgetPanelType;
  sidebar: ReactNode;
  thread: ReactNode;
};
