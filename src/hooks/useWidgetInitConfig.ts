import { useContext } from 'react';
import { WidgetInitConfigContext } from '../contexts/config-provider';
import type { WidgetFeatures, WidgetInitConfig } from '../schemas/widget.schemas';

export function useWidgetInitConfig(): WidgetInitConfig {
  const ctx = useContext(WidgetInitConfigContext);
  if (!ctx) {
    throw new Error('useWidgetInitConfig must be used within WidgetInitConfigProvider');
  }
  return ctx;
}

export function useWidgetFeatures(): WidgetFeatures {
  return useWidgetInitConfig().features;
}
