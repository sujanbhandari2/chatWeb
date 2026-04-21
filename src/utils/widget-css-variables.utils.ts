import { defaultWidgetInitConfig, type WidgetInitConfig } from '../schemas/widget.schemas';

/** Apply resolved widget config to an element as `--widget-*` custom properties (cascade to descendants). */
export function applyWidgetCssVariables(root: HTMLElement, config: WidgetInitConfig): void {
  const colors = config.colors ?? defaultWidgetInitConfig.colors!;
  const typography = config.typography ?? defaultWidgetInitConfig.typography!;
  const spacing = config.spacing ?? defaultWidgetInitConfig.spacing!;
  const fs = typography.fontSize;
  const fw = typography.fontWeight;

  if (colors) {
    root.style.setProperty('--widget-primary', colors.primary);
    root.style.setProperty('--widget-secondary', colors.secondary);
    root.style.setProperty('--widget-accent', colors.accent);
    root.style.setProperty('--widget-background', colors.background);
    root.style.setProperty('--widget-surface', colors.surface);
    root.style.setProperty('--widget-border', colors.border);
    /** Text on top of primary (outgoing bubbles, send button). */
    root.style.setProperty('--widget-on-primary', colors.text?.inverse ?? '#ffffff');
    if (colors.text) {
      root.style.setProperty('--widget-text-primary', colors.text.primary);
      root.style.setProperty('--widget-text-secondary', colors.text.secondary);
      root.style.setProperty('--widget-text-tertiary', colors.text.tertiary);
      root.style.setProperty('--widget-text-inverse', colors.text.inverse);
    }
    if (colors.status) {
      root.style.setProperty('--widget-success', colors.status.success);
      root.style.setProperty('--widget-error', colors.status.error);
      root.style.setProperty('--widget-warning', colors.status.warning);
      root.style.setProperty('--widget-info', colors.status.info);
    }
  }

  root.style.setProperty('--widget-font-family', typography.fontFamily);
  root.style.setProperty('--widget-font-size-xs', `${fs.xs}px`);
  root.style.setProperty('--widget-font-size-sm', `${fs.sm}px`);
  root.style.setProperty('--widget-font-size-base', `${fs.base}px`);
  root.style.setProperty('--widget-font-size-lg', `${fs.lg}px`);
  root.style.setProperty('--widget-font-size-xl', `${fs.xl}px`);
  root.style.setProperty('--widget-font-size-2xl', `${fs['2xl']}px`);
  root.style.setProperty('--widget-font-weight-light', String(fw.light));
  root.style.setProperty('--widget-font-weight-normal', String(fw.normal));
  root.style.setProperty('--widget-font-weight-medium', String(fw.medium));
  root.style.setProperty('--widget-font-weight-semibold', String(fw.semibold));
  root.style.setProperty('--widget-font-weight-bold', String(fw.bold));
  root.style.setProperty('--widget-line-height', String(typography.lineHeight));
  root.style.setProperty('--widget-letter-spacing', String(typography.letterSpacing));

  root.style.setProperty('--widget-panel-width', `${spacing.panelWidth}px`);
  root.style.setProperty('--widget-panel-height', `${spacing.panelHeight}px`);
  root.style.setProperty('--widget-launcher-size', `${spacing.launcherSize}px`);
  root.style.setProperty('--widget-panel-radius', spacing.panelBorderRadius);
  root.style.setProperty('--widget-panel-shadow', spacing.panelBoxShadow);
  root.style.setProperty('--widget-z-index', String(config.zIndex));
}
