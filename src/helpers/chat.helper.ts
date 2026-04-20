import { PANEL_LABEL_MAP } from "../constants/chat.constant";
import { WidgetInitConfig } from "../schemas/widget.schemas";
import { WidgetPanelType } from "../types/chat";

/** @deprecated Embed no longer requires `backend.companyId` for API calls; kept for callers that still import it. */
export function isValidTenantConfiguration(_config: WidgetInitConfig): boolean {
  return true;
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