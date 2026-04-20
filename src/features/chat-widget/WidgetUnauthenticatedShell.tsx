import { wrapWidgetContent, WidgetUnauthenticatedContent } from './widget-shell';
import type { WidgetUnauthenticatedShellProps } from '../../types/widget-app.types';

/** User bootstrap form when the visitor has not completed `POST /api/v1/chat/users` yet. */
export function WidgetUnauthenticatedShell({
  config,
  isMissingTenant
}: WidgetUnauthenticatedShellProps): JSX.Element {
  return wrapWidgetContent(
    config,
    <WidgetUnauthenticatedContent config={config} widgetMissingTenant={isMissingTenant} />,
    { panelInitiallyOpen: true }
  );
}
