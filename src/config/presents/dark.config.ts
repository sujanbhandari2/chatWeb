import { applyThemePreset, WidgetInitConfig } from "../../schemas/widget.schemas";

export const exampleDarkConfig: WidgetInitConfig = applyThemePreset('dark', {
    spacing: {
      launcherSize: 60
    }
  });