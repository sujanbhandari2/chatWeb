import type { CSSProperties, ReactNode } from 'react';
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { resolveWidgetShellSections, type WidgetInitConfig } from '../../schemas/widget.schemas';
import type { AuthUser } from '../../types/chat';
import { applyWidgetCssVariables } from '../../utils/widget-css-variables.utils';
import { postWidgetEmbedResizeToParent } from '../../utils/widget-embed-resize.utils';
import { userDisplayName, userInitials } from '../../utils/chat.utils';

function cn(...parts: Array<string | undefined | false>): string {
  return parts.filter(Boolean).join(' ');
}

export type WidgetChatProps = {
  config: WidgetInitConfig;
  children: ReactNode;
  panelHeaderCenterText?: string;
  /** Shown compact, immediately left of the panel close control */
  panelHeaderUser?: AuthUser;
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

/** Floating chat button and slide-out panel; renders `children` inside the panel. */
export function WidgetChat({ config, children, panelHeaderCenterText, panelHeaderUser }: WidgetChatProps): JSX.Element {
  const panelId = useId().replace(/:/g, '');
  const rootRef = useRef<HTMLDivElement>(null);
  const launcherRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const configRef = useRef(config);
  configRef.current = config;

  const { interactions, spacing, launcher, typography, colors, uiElements, styling } =
    resolveWidgetShellSections(config);
  const brandPrefix = styling.classPrefix;

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

  /**
   * Shrink host iframe when panel closes so transparent area does not block the page (loader listens).
   * useLayoutEffect runs before paint so the parent can resize the iframe before the user sees a tall empty box.
   */
  useLayoutEffect(() => {
    const notify = (): void => {
      postWidgetEmbedResizeToParent(open, configRef.current);
    };
    notify();
    window.addEventListener('resize', notify);
    return () => window.removeEventListener('resize', notify);
  }, [open]);

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
    <div ref={rootRef} className={cn('vcw-root', `${brandPrefix}-root`)}>
      <button
        ref={launcherRef}
        type="button"
        className={cn('vcw-launcher', `${brandPrefix}-launcher`)}
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
          className={cn('vcw-panel', `${brandPrefix}-panel`)}
          style={panelStyle}
          role="dialog"
          aria-modal="true"
          aria-label={panelTitle ?? panelHeaderCenterText ?? ariaLabel}
          tabIndex={-1}
        >
          <div className={cn('vcw-panel-header', `${brandPrefix}-panel-header`)}>
            {panelTitle ? (
              <span className={cn('vcw-panel-title', `${brandPrefix}-panel-title`)}>{panelTitle}</span>
            ) : panelHeaderCenterText ? (
              <span
                className={cn(
                  'vcw-panel-title',
                  'vcw-panel-title--centered',
                  `${brandPrefix}-panel-title`,
                  `${brandPrefix}-panel-title--centered`,
                )}
              >
                {panelHeaderCenterText}
              </span>
            ) : (
              <span
                className={cn(
                  'vcw-panel-title',
                  'vcw-panel-title--placeholder',
                  `${brandPrefix}-panel-title`,
                  `${brandPrefix}-panel-title--placeholder`,
                )}
                aria-hidden
              />
            )}
            {panelHeaderUser ? (
              <div
                className={cn('vcw-panel-header-profile', `${brandPrefix}-panel-header-profile`)}
                aria-label={`Signed in as ${userDisplayName({ name: panelHeaderUser.name, email: panelHeaderUser.email })}`}
              >
                <div className={cn('vcw-panel-header-avatar', `${brandPrefix}-panel-header-avatar`)} aria-hidden>
                  {userInitials({ name: panelHeaderUser.name, email: panelHeaderUser.email })}
                </div>
                <span className={cn('vcw-panel-header-name', `${brandPrefix}-panel-header-name`)}>
                  {userDisplayName({ name: panelHeaderUser.name, email: panelHeaderUser.email })}
                </span>
              </div>
            ) : null}
            <button
              type="button"
              className={cn('vcw-panel-close', `${brandPrefix}-panel-close`)}
              onClick={close}
              aria-label="Close chat"
            >
              ×
            </button>
          </div>
          <div className={cn('vcw-panel-body', `${brandPrefix}-panel-body`)}>{children}</div>
        </div>
      )}
    </div>
  );
}
