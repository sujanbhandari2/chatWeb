import { PANEL_LABEL_MAP } from "../constants/chat.constant";
import { WidgetInitConfig } from "../schemas/widget.schemas";
import { WidgetPanelType } from "../types/chat";

/**
 * Validates that the widget configuration has a valid tenant ID
 */
export function isValidTenantConfiguration(config: WidgetInitConfig): boolean {
    return Boolean(config.backend?.tenantId?.trim());
  }
   
  /**
   * Gets the appropriate panel header label based on the current panel type
   */
  export function getPanelHeaderLabel(panelType: WidgetPanelType): string {
    return PANEL_LABEL_MAP[panelType] || PANEL_LABEL_MAP[WidgetPanelType.CHATS];
  }
   
  /**
   * Determines if the chat overlay should be visible
   */
  export function isChatOverlayVisible(
    selectedConversationId: string | null,
    currentPanel: WidgetPanelType
  ): boolean {
    return Boolean(selectedConversationId) && currentPanel === WidgetPanelType.CHATS;
  }