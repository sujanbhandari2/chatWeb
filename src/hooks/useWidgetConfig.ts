import { defaultWidgetInitConfig, type WidgetInitConfig } from '../schemas/widget.schemas';
import { useAuthStore } from '../store/useAuthStore';
import { useChatSelectors } from './useChatSelectors';
import { selectWidgetChrome } from '../store/chat/chat-selectors';
import { useChatRuntime } from './useChatRuntime';
import { getPanelHeaderLabel, isChatOverlayVisible } from '../helpers/chat.helper';
import type { WidgetConfigState } from '../types/widget-app.types';

/**
 * Resolved widget config, auth session, chat runtime, and rail/header UI derived state for the embed.
 */
export function useWidgetConfig(optionalConfig?: WidgetInitConfig): WidgetConfigState {
  const config = optionalConfig ?? defaultWidgetInitConfig;
  const runtime = useChatRuntime(config);

  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const sessionHydrated = useAuthStore((s) => s.sessionHydrated);

  const { widgetRailPane, selectedConversationId } = useChatSelectors(selectWidgetChrome);

  /** Tenant is optional when `X-Api-Key` is set; do not block the auth form. */
  const isMissingTenant = false;
  const headerLabel = getPanelHeaderLabel(widgetRailPane);
  const overlayVisible = isChatOverlayVisible(selectedConversationId, widgetRailPane);

  return {
    config,
    runtime,
    token,
    user,
    sessionHydrated,
    currentPanel: widgetRailPane,
    selectedConversationId,
    isMissingTenant,
    headerLabel,
    overlayVisible,
  };
}

export type { WidgetConfigState } from '../types/widget-app.types';
