import { mergeConfig, type WidgetInitConfig } from '../../schemas/widget.schemas';

export const customConfig: WidgetInitConfig = mergeConfig({
    colors: {
      primary: '#6366f1',
      secondary: '#06b6d4',
      accent: '#f97316'
    },
    spacing: {
      launcherSize: 64,
      panelWidth: 420,
      panelHeight: 600
    },
    launcher: {
      position: 'left',
      badge: {
        enabled: true,
        backgroundColor: '#ef4444',
        textColor: '#ffffff',
        count: 3
      }
    },
  });
  