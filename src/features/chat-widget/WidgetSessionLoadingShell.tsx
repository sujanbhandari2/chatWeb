import { wrapWidgetContent, WidgetSessionLoadingContent } from './widget-shell';
import type { WidgetSessionLoadingShellProps } from '../../types/widget-app.types';

/** Session restoring UI inside the floating widget. */
export function WidgetSessionLoadingShell({ config }: WidgetSessionLoadingShellProps): JSX.Element {
  return wrapWidgetContent(config, <WidgetSessionLoadingContent />, { panelInitiallyOpen: true });
}
