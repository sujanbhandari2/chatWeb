import type {
  selectCreateGroupForm,
  selectEditGroupForm,
  selectRuntimeSubscriptionSlice,
  selectSidebarRails,
  selectThreadView,
  selectWidgetChrome
} from '../store/chat/chat-selectors';

export type WidgetChromeSlice = ReturnType<typeof selectWidgetChrome>;
export type RuntimeSubscriptionSlice = ReturnType<typeof selectRuntimeSubscriptionSlice>;
export type ChatThreadViewSlice = ReturnType<typeof selectThreadView>;
export type SidebarRailsSlice = ReturnType<typeof selectSidebarRails>;
export type CreateGroupFormSlice = ReturnType<typeof selectCreateGroupForm>;
export type EditGroupFormSlice = ReturnType<typeof selectEditGroupForm>;
