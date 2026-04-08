import type { CSSProperties, ReactNode } from 'react';
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { defaultWidgetInitConfig, type WidgetInitConfig } from '../../schemas/widget.schemas';
import { applyWidgetCssVariables } from '../../utils/widget-css-variables.utils';

type ChatWidgetShellProps = {
  config: WidgetInitConfig;
  children: ReactNode;
  /** Shown in the panel header when `config.uiElements.panelTitle` is not set (e.g. "Chats"). */
  panelHeaderCenterText?: string;
};

function getFocusableElements(root: HTMLElement): HTMLElement[] {
  const sel =
    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(root.querySelectorAll<HTMLElement>(sel)).filter(
    (el) => el.offsetParent !== null || el === document.activeElement
  );
}

function isHorizontalLeft(position: string): boolean {
  return position === 'left' || position === 'bottom-left';
}

export function ChatWidgetShell({ config, children, panelHeaderCenterText }: ChatWidgetShellProps): JSX.Element {
  const panelId = useId().replace(/:/g, '');
  const rootRef = useRef<HTMLDivElement>(null);
  const launcherRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  const interactions = config.interactions ?? defaultWidgetInitConfig.interactions!;
  const spacing = config.spacing ?? defaultWidgetInitConfig.spacing!;
  const launcher = config.launcher ?? defaultWidgetInitConfig.launcher!;
  const typography = config.typography ?? defaultWidgetInitConfig.typography!;
  const colors = config.colors ?? defaultWidgetInitConfig.colors!;
  const uiElements = config.uiElements ?? defaultWidgetInitConfig.uiElements!;

  const [open, setOpen] = useState(interactions.defaultOpen);

  const close = useCallback((): void => {
    setOpen(false);
    window.setTimeout(() => launcherRef.current?.focus(), 0);
  }, []);

  const toggle = useCallback((): void => {
    setOpen((o) => !o);
  }, []);

  useLayoutEffect(() => {
    const el = rootRef.current;
    if (el) {
      applyWidgetCssVariables(el, config);
    }
  }, [config]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const panel = panelRef.current;
    if (!panel) {
      return undefined;
    }
    const focusables = getFocusableElements(panel);
    const first = focusables[0];
    if (first) {
      first.focus();
    }

    const onKeyDown = (e: KeyboardEvent): void => {
      if (interactions.closeOnEscape && e.key === 'Escape') {
        e.preventDefault();
        close();
        return;
      }
      if (e.key !== 'Tab' || focusables.length === 0) {
        return;
      }
      const firstEl = focusables[0];
      const lastEl = focusables[focusables.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === firstEl) {
          e.preventDefault();
          lastEl.focus();
        }
      } else if (document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    };

    panel.addEventListener('keydown', onKeyDown);
    return () => panel.removeEventListener('keydown', onKeyDown);
  }, [open, interactions.closeOnEscape, close]);

  useEffect(() => {
    if (!open || !interactions.closeOnClickOutside) {
      return undefined;
    }
    const onMouseDown = (e: MouseEvent): void => {
      const t = e.target as Node;
      if (panelRef.current?.contains(t) || launcherRef.current?.contains(t)) {
        return;
      }
      close();
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => document.removeEventListener('mousedown', onMouseDown);
  }, [open, interactions.closeOnClickOutside, close]);

  const position = launcher.position;
  const isRight = !isHorizontalLeft(position);
  const launcherSize = launcher.size;
  const textInverse = colors.text?.inverse ?? '#ffffff';

  const launcherStyle: CSSProperties = {
    position: 'fixed',
    bottom: spacing.offsetBottom,
    [isRight ? 'right' : 'left']: spacing.offsetSide,
    width: launcherSize,
    height: launcherSize,
    zIndex: config.zIndex,
    borderRadius: '999px',
    border: 'none',
    padding: 0,
    fontFamily: typography.fontFamily,
    fontSize: typography.fontSize.base,
    fontWeight: typography.fontWeight.medium,
    lineHeight: typography.lineHeight,
    letterSpacing: typography.letterSpacing,
    textAlign: 'center',
    color: textInverse,
    backgroundColor: 'var(--widget-primary, #2563eb)',
    cursor: 'pointer',
    boxShadow: '0 4px 14px rgba(15, 23, 42, 0.2)',
    display: 'grid',
    placeItems: 'center',
    overflow: 'hidden'
  };

  const panelStyle: CSSProperties = {
    position: 'fixed',
    bottom: spacing.offsetBottom + launcherSize + 12,
    [isRight ? 'right' : 'left']: spacing.offsetSide,
    width: spacing.panelWidth,
    height: spacing.panelHeight,
    maxWidth: spacing.panelMaxWidth ?? 'min(100vw - 32px, 96vw)',
    maxHeight: spacing.panelMaxHeight ?? 'min(100vh - 32px, 92vh)',
    zIndex: config.zIndex,
    borderRadius: spacing.panelBorderRadius,
    boxShadow: spacing.panelBoxShadow,
    background: 'var(--widget-surface, #f8fafc)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    outline: 'none'
  };

  const panelTitle = uiElements.panelTitle;
  const ariaLabel = launcher.ariaLabel;

  return (
    <div ref={rootRef} className="chat-widget-root">
      <button
        ref={launcherRef}
        type="button"
        className="chat-widget-launcher"
        style={launcherStyle}
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={ariaLabel}
        onClick={toggle}
      >
        {launcher.iconUrl ? (
          <img src={launcher.iconUrl} alt="" width={28} height={28} style={{ objectFit: 'cover' }} />
        ) : (
          <span style={{ fontSize: '1.35rem', lineHeight: 1 }} aria-hidden>
            💬
          </span>
        )}
      </button>

      {open && (
        <div
          ref={panelRef}
          id={panelId}
          className="chat-widget-panel"
          style={panelStyle}
          role="dialog"
          aria-modal="true"
          aria-label={panelTitle ?? panelHeaderCenterText ?? ariaLabel}
          tabIndex={-1}
        >
          <div className="chat-widget-panel-header">
            {panelTitle ? (
              <span className="chat-widget-panel-title">{panelTitle}</span>
            ) : panelHeaderCenterText ? (
              <span className="chat-widget-panel-title chat-widget-panel-title--centered">{panelHeaderCenterText}</span>
            ) : (
              <span className="chat-widget-panel-title chat-widget-panel-title--placeholder" aria-hidden />
            )}
            <button type="button" className="chat-widget-panel-close" onClick={close} aria-label="Close chat">
              ×
            </button>
          </div>
          <div className="chat-widget-panel-body">{children}</div>
        </div>
      )}
    </div>
  );
}
