import { wrapWidgetContent, WidgetUnauthenticatedContent } from './widget-shell';
import type { WidgetUnauthenticatedShellProps } from '../../types/widget-app.types';

/** Login / tenant messaging when the user is not signed in. */
export function WidgetUnauthenticatedShell({
  config,
  isMissingTenant
}: WidgetUnauthenticatedShellProps): JSX.Element {
  return wrapWidgetContent(
    config,
    <WidgetUnauthenticatedContent widgetMissingTenant={isMissingTenant} />
  );
}
