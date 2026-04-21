import { applyThemePreset, WidgetInitConfig } from "../../schemas/widget.schemas";

export const exampleBrandConfig: WidgetInitConfig = applyThemePreset('brand', {
    uiElements: {
      showHeader: true,
      showFooter: true,
      panelTitle: 'Welcome to our support',
      showBranding: true,
      brandingText: 'Powered by VSuite'
    },
    launcher: {
      position: 'bottom-right',
      badge: {
        enabled: true,
        backgroundColor: '#ec4899',
        textColor: '#ffffff'
      }
    }
  });
  