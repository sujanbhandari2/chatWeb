import { defaultWidgetInitConfig, type WidgetInitConfig } from '../schemas/widget.schemas';

/** Matches `public/healthchat-widget-loader.js` postMessage protocol. */
export const WIDGET_EMBED_MESSAGE_SOURCE = 'healthchat-widget';

export type WidgetEmbedResizeMessage = {
  source: typeof WIDGET_EMBED_MESSAGE_SOURCE;
  type: 'resize';
  width: number;
  height: number;
};

/**
 * Pixel size for the embed iframe (host window coordinates). Must stay in sync with
 * `iframeBox()` in `public/healthchat-widget-loader.js`.
 */
export function getWidgetEmbedIframeSizePx(panelOpen: boolean, config: WidgetInitConfig): { width: number; height: number } {
  const spacing = config.spacing ?? defaultWidgetInitConfig.spacing!;
  const launcher = config.launcher ?? defaultWidgetInitConfig.launcher!;
  const w = spacing.panelWidth;
  const h = spacing.panelHeight;
  const ls = launcher.size;
  const vw = typeof window !== 'undefined' ? window.innerWidth : 800;
  const vh = typeof window !== 'undefined' ? window.innerHeight : 600;

  if (panelOpen) {
    return {
      width: Math.min(w + 40, vw - 16),
      height: Math.min(h + ls + 56, vh - 16),
    };
  }

  return {
    width: Math.min(ls + spacing.offsetSide + 40, vw - 16),
    height: Math.min(ls + spacing.offsetBottom + 40, vh - 16),
  };
}

export function postWidgetEmbedResizeToParent(panelOpen: boolean, config: WidgetInitConfig): void {
  if (typeof window === 'undefined' || window.parent === window) {
    return;
  }
  const { width, height } = getWidgetEmbedIframeSizePx(panelOpen, config);
  const msg: WidgetEmbedResizeMessage = {
    source: WIDGET_EMBED_MESSAGE_SOURCE,
    type: 'resize',
    width,
    height,
  };
  window.parent.postMessage(msg, '*');
}
