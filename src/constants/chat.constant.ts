import { WidgetPanelType } from "../types/chat";

export const PANEL_LABEL_MAP: Record<WidgetPanelType, string> = {
    [WidgetPanelType.CHATS]: 'Chats',
    [WidgetPanelType.PEOPLE]: 'People',
    [WidgetPanelType.NEW_GROUP]: 'New group',
    [WidgetPanelType.EDIT_GROUP]: 'Edit group',
  };