import { createContext, type ReactNode } from 'react';
import type { WidgetInitConfig } from '../schemas/widget.schemas';

const WidgetInitConfigContext = createContext<WidgetInitConfig | null>(null);

export { WidgetInitConfigContext };

export function WidgetInitConfigProvider({
  value,
  children,
}: {
  value: WidgetInitConfig;
  children: ReactNode;
}): JSX.Element {
  return (
    <WidgetInitConfigContext.Provider value={value}>{children}</WidgetInitConfigContext.Provider>
  );
}
