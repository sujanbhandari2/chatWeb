/**
 * Rich demo preset (`VITE_WIDGET_PROFILE=full`). Uses demo `backend` URLs — not for a real local API.
 * Built from `mergeConfig` partials only (defaults come from `defaultWidgetInitConfig`).
 */
import { mergeConfig, WidgetInitConfig } from "../../schemas/widget.schemas";
export const exampleFullConfig: WidgetInitConfig = mergeConfig({
    typography: {
      fontFamily: '"Segoe UI", Tahoma, Geneva, Verdana, sans-serif',
      fontSize: {
        xs: 12,
        sm: 14,
        base: 16,
        lg: 18,
        xl: 20,
        '2xl': 24
      },
      fontWeight: {
        light: 300,
        normal: 400,
        medium: 500,
        semibold: 600,
        bold: 700
      },
      lineHeight: 1.6,
      letterSpacing: 0.5
    },
    spacing: {
      offsetBottom: 32,
      offsetSide: 32,
      launcherSize: 60,
      panelWidth: 400,
      panelHeight: 600,
      panelBorderRadius: '16px',
      panelBoxShadow: '0 20px 50px rgba(0, 0, 0, 0.2)'
    },
    launcher: {
      size: 60,
      iconUrl: '/assets/chat-icon.svg',
      ariaLabel: 'Open support chat',
      position: 'bottom-right',
      badge: {
        enabled: true,
        backgroundColor: '#ef4444',
        textColor: '#ffffff',
        count: 2
      }
    },
    interactions: {
      animationDuration: 400
    },
    uiElements: {
      panelTitle: 'Chat with us',
      showHeader: true,
      showFooter: true,
      showBranding: true,
      brandingText: 'Powered by WidgetChat',
      headerIconUrl: '/assets/logo.svg'
    },
    backend: {
      tenantId: 'my-company',
      lockTenant: false,
      hideTenantField: false,
      apiUrl: 'https://api.example.com',
      socketUrl: 'wss://socket.example.com',
      apiTimeout: 30000,
      retryAttempts: 3
    },
    a11y: {
      ariaDescribedBy: 'chat-help-text'
    },
    features: {
      imageUpload: false,
      audioAttachmentUpload: false
    },
    app: {
      releaseVersion: 'example-full-profile'
    },
    debug: false
  });