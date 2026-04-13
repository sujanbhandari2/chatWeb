import { wrapWidgetContent, WidgetUnauthorizedContent } from './widget-shell';
import type { WidgetUnauthorizedShellProps } from '../../types/widget-app.types';

/** Shown when the host did not supply a valid embed credential (`accessKey` / API key). */
export function WidgetUnauthorizedShell({ config }: WidgetUnauthorizedShellProps): JSX.Element {
  return wrapWidgetContent(config, <WidgetUnauthorizedContent />);
}
