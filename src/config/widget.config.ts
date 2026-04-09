import {
  mergeConfig,
  applyThemePreset,
  type DeepPartialWidgetConfig
} from '../schemas/widget.schemas';
import { customConfig } from './presents/custom.config';
import { exampleDarkConfig } from './presents/dark.config';
import { exampleBrandConfig } from './presents/brand.config';
import { exampleFullConfig } from './presents/full.config';
import { devSandboxPartial } from './sandbox/dev';
import { prodSandboxPartial } from './sandbox/prod';

export const widgetConfigExamples = {
  custom: customConfig,
  dark: exampleDarkConfig,
  brand: exampleBrandConfig,
  full: exampleFullConfig
} as const;

export type WidgetConfigExampleKey = keyof typeof widgetConfigExamples;

export const configs = {
  development: mergeConfig({
    debug: true,
    ...devSandboxPartial,
  }),
  staging: applyThemePreset('light', {

  }),
  production: applyThemePreset('light', {
    ...prodSandboxPartial,
  })
} as const;

const PROFILE_KEYS = ['development', 'staging', 'production'] as const;
type ProfileKey = (typeof PROFILE_KEYS)[number];

const EXAMPLE_KEYS = ['custom', 'dark', 'brand', 'full'] as const;
type ExampleKey = (typeof EXAMPLE_KEYS)[number];

function isProfileKey(k: string): k is ProfileKey {
  return (PROFILE_KEYS as readonly string[]).includes(k);
}

function isExampleKey(k: string): k is ExampleKey {
  return (EXAMPLE_KEYS as readonly string[]).includes(k);
}

export function getWidgetProfilePartial(): DeepPartialWidgetConfig {
  const explicit =
    typeof import.meta.env.VITE_WIDGET_PROFILE === 'string'
      ? import.meta.env.VITE_WIDGET_PROFILE.trim().toLowerCase()
      : '';
  const mode = (import.meta.env.MODE ?? 'development').toLowerCase();

  if (explicit && isExampleKey(explicit)) {
    return widgetConfigExamples[explicit];
  }

  const key: ProfileKey =
    explicit && isProfileKey(explicit) ? explicit : isProfileKey(mode) ? mode : 'development';
  return configs[key];
}
