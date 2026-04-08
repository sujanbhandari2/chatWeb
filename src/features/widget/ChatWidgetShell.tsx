import type { CSSProperties, ReactNode } from 'react';
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { WidgetInitConfig } from '../../schemas/widget.schemas';

type ChatWidgetShellProps = {
  config: WidgetInitConfig;
  children: ReactNode;
};

function getFocusableElements(root: HTMLElement): HTMLElement[] {
  const sel =
    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(root.querySelectorAll<HTMLElement>(sel)).filter(
    (el) => el.offsetParent !== null || el === document.activeElement
  );
}

export function ChatWidgetShell({ config, children }: ChatWidgetShellProps): JSX.Element {
  const panelId = useId().replace(/:/g, '');
  const launcherRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(config.defaultOpen);

  const close = useCallback((): void => {
    setOpen(false);
    window.setTimeout(() => launcherRef.current?.focus(), 0);
  }, []);

  const toggle = useCallback((): void => {
    setOpen((o) => !o);
  }, []);

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
      if (config.closeOnEscape && e.key === 'Escape') {
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
  }, [open, config.closeOnEscape, close]);

  useEffect(() => {
    if (!open || !config.closeOnClickOutside) {
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
  }, [open, config.closeOnClickOutside, close]);

  const isRight = config.position === 'right';
  const launcherStyle: CSSProperties = {
    position: 'fixed',
    bottom: config.offsetBottom,
    [isRight ? 'right' : 'left']: config.offsetSide,
    width: config.launcherSize,
    height: config.launcherSize,
    zIndex: config.zIndex,
    borderRadius: '999px',
    border: 'none',
    padding: 0,
    cursor: 'pointer',
    boxShadow: '0 4px 14px rgba(15, 23, 42, 0.2)',
    background: '#0084ff',
    color: '#fff',
    display: 'grid',
    placeItems: 'center',
    overflow: 'hidden'
  };

  const panelStyle: CSSProperties = {
    position: 'fixed',
    bottom: config.offsetBottom + config.launcherSize + 12,
    [isRight ? 'right' : 'left']: config.offsetSide,
    width: config.panelWidth,
    height: config.panelHeight,
    maxWidth: config.panelMaxWidth ?? 'min(100vw - 32px, 96vw)',
    maxHeight: config.panelMaxHeight ?? 'min(100vh - 32px, 92vh)',
    zIndex: config.zIndex,
    borderRadius: config.panelBorderRadius,
    boxShadow: config.panelBoxShadow,
    background: '#f0f2f5',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    outline: 'none'
  };

  return (
    <div className="chat-widget-root">
      <button
        ref={launcherRef}
        type="button"
        className="chat-widget-launcher"
        style={launcherStyle}
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={config.launcherAriaLabel}
        onClick={toggle}
      >
        {config.launcherIconUrl ? (
          <img src={config.launcherIconUrl} alt="" width={28} height={28} style={{ objectFit: 'cover' }} />
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
          aria-label={config.panelTitle ?? config.launcherAriaLabel}
          tabIndex={-1}
        >
          <div className="chat-widget-panel-header">
            {config.panelTitle ? (
              <span className="chat-widget-panel-title">{config.panelTitle}</span>
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
