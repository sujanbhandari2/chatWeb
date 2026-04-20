import { z } from 'zod';
import { a11ySchema } from './widget/a11y.schema';
import { appSchema, defaultWidgetApp } from './widget/app.schema';
import { backendSchema } from './widget/backend.schema';
import { colorPaletteSchema } from './widget/color.schema';
import { defaultWidgetFeatures, featuresSchema } from './widget/features.schema';
import { interactionSchema } from './widget/interaction.schema';
import { launcherSchema } from './widget/launcher.schema';
import { spacingSchema } from './widget/spacing.schema';
import { stylingSchema } from './widget/styling.schema';
import { typographySchema } from './widget/typography.schema';
import { uiElementsSchema } from './widget/ui-elements.schema';

export {
  appSchema,
  defaultWidgetApp,
} from './widget/app.schema';
export type { WidgetApp } from './widget/app.schema';
export {
  defaultWidgetFeatures,
  featuresSchema,
} from './widget/features.schema';
export type { WidgetFeatures } from './widget/features.schema';

/**
 * Main widget configuration schema — single source of truth
 */
export const widgetInitConfigSchema = z.object({
  // Core branding & colors
  colors: colorPaletteSchema.optional(),
  // Typography
  typography: typographySchema.optional(),
  // Layout & spacing
  spacing: spacingSchema.optional(),
  // Launcher (floating button)
  launcher: launcherSchema.optional(),
  // Interactions
  interactions: interactionSchema.optional(),
  // UI Elements
  uiElements: uiElementsSchema.optional(),
  // Backend/API
  backend: backendSchema.optional(),
  // Accessibility
  a11y: a11ySchema.optional(),
  /** Admin/build: optional host CSS hooks (`.{classPrefix}-root`, …); ignored from embed URL/window. */
  styling: stylingSchema.default({ classPrefix: 'vitafy-chat' }),
  /** Feature gates for multi-tenant widget builds; not overridable from untrusted embed config. */
  features: featuresSchema.default(defaultWidgetFeatures),
  /** Schema version + release string; not overridable from untrusted embed config. */
  app: appSchema.default(defaultWidgetApp),
  // Global settings
  zIndex: z.number().default(99999),
  debug: z.boolean().default(false),
});

export type WidgetInitConfig = z.infer<typeof widgetInitConfigSchema>;

type StripUndefined<T> = T extends undefined ? never : T;

/** Nested partial embed / patch shape (URL, window config, UI editors). */
export type DeepPartialWidgetConfig = {
  [K in keyof WidgetInitConfig]?: StripUndefined<WidgetInitConfig[K]> extends object
    ? SubPartial<StripUndefined<WidgetInitConfig[K]>>
    : WidgetInitConfig[K];
};

type SubPartial<T> = {
  [K in keyof T]?: T[K] extends object ? SubPartial<T[K]> : T[K];
};

/**
 * Default configuration with all sensible defaults
 */
export const defaultWidgetInitConfig: WidgetInitConfig = widgetInitConfigSchema.parse({
  colors: {
    primary: '#2563eb',
    secondary: '#64748b',
    accent: '#f59e0b',
    background: '#ffffff',
    surface: '#f8fafc',
    border: '#e2e8f0',
    text: {
      primary: '#1e293b',
      secondary: '#64748b',
      tertiary: '#94a3b8',
      inverse: '#ffffff',
    },
    status: {
      success: '#10b981',
      error: '#ef4444',
      warning: '#f59e0b',
      info: '#0ea5e9',
    },
  },
  typography: {
    fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: {
      xs: 12,
      sm: 14,
      base: 16,
      lg: 18,
      xl: 20,
      '2xl': 24,
    },
    fontWeight: {
      light: 300,
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
    },
    lineHeight: 1.5,
    letterSpacing: 0,
  },
  spacing: {
    offsetBottom: 24,
    offsetSide: 24,
    launcherSize: 56,
    panelWidth: 380,
    panelHeight: 560,
    panelBorderRadius: '12px',
    panelBoxShadow: '0 12px 40px rgba(15, 23, 42, 0.15)',
  },
  launcher: {
    size: 56,
    ariaLabel: 'Open chat',
    position: 'right',
  },
  interactions: {
    closeOnEscape: true,
    closeOnClickOutside: true,
    defaultOpen: true,
    animationEnabled: true,
    animationDuration: 300,
  },
  uiElements: {
    showHeader: true,
    showFooter: true,
    showBranding: false,
  },
  backend: {
    apiTimeout: 30000,
    retryAttempts: 3,
  },
  a11y: {
    ariaLabel: 'Chat widget',
    reduceMotion: false,
    highContrast: false,
  },
  zIndex: 99999,
  debug: false,
});

/**
 * Pre-configured theme presets for quick setup
 */
export const themePresets = {
  light: {
    colors: {
      primary: '#2563eb',
      secondary: '#64748b',
      accent: '#f59e0b',
      background: '#ffffff',
      surface: '#f8fafc',
      border: '#e2e8f0',
      text: {
        primary: '#1e293b',
        secondary: '#64748b',
        tertiary: '#94a3b8',
        inverse: '#ffffff',
      },
    },
  },
  dark: {
    colors: {
      primary: '#3b82f6',
      secondary: '#9ca3af',
      accent: '#fbbf24',
      background: '#1f2937',
      surface: '#111827',
      border: '#374151',
      text: {
        primary: '#f3f4f6',
        secondary: '#d1d5db',
        tertiary: '#9ca3af',
        inverse: '#1f2937',
      },
    },
  },
  brand: {
    colors: {
      primary: '#7c3aed', // Purple
      secondary: '#06b6d4', // Cyan
      accent: '#ec4899', // Pink
      background: '#ffffff',
      surface: '#f5f3ff',
      border: '#ede9fe',
      text: {
        primary: '#4c1d95',
        secondary: '#6d28d9',
        tertiary: '#a78bfa',
        inverse: '#ffffff',
      },
    },
  },
} as const;

/**
 * Helper function to merge custom config with defaults
 */
const defaultLauncherBadge = {
  enabled: false,
  backgroundColor: '#ef4444',
  textColor: '#ffffff'
} as const;

function defaultReleaseVersionFromEnv(): string {
  return typeof import.meta !== 'undefined' && import.meta.env?.VITE_APP_VERSION
    ? String(import.meta.env.VITE_APP_VERSION)
    : 'dev';
}

export function mergeConfig(custom?: DeepPartialWidgetConfig): WidgetInitConfig {
  const dc = defaultWidgetInitConfig.colors!;
  const dt = defaultWidgetInitConfig.typography!;
  const dl = defaultWidgetInitConfig.launcher!;
  const df = defaultWidgetInitConfig.features!;
  const da = defaultWidgetInitConfig.app!;
  const mergedAppBase = { ...da, ...custom?.app };
  return widgetInitConfigSchema.parse({
    ...defaultWidgetInitConfig,
    ...custom,
    colors: {
      ...dc,
      ...custom?.colors,
      text: { ...dc.text, ...custom?.colors?.text },
      status: { ...dc.status, ...custom?.colors?.status }
    },
    typography: {
      ...dt,
      ...custom?.typography,
      fontSize: { ...dt.fontSize, ...custom?.typography?.fontSize },
      fontWeight: { ...dt.fontWeight, ...custom?.typography?.fontWeight }
    },
    spacing: { ...defaultWidgetInitConfig.spacing, ...custom?.spacing },
    launcher: {
      ...dl,
      ...custom?.launcher,
      badge:
        custom?.launcher?.badge != null
          ? {
              ...defaultLauncherBadge,
              ...dl.badge,
              ...custom.launcher.badge
            }
          : dl.badge
    },
    interactions: { ...defaultWidgetInitConfig.interactions, ...custom?.interactions },
    uiElements: { ...defaultWidgetInitConfig.uiElements, ...custom?.uiElements },
    backend: { ...defaultWidgetInitConfig.backend, ...custom?.backend },
    a11y: { ...defaultWidgetInitConfig.a11y, ...custom?.a11y },
    features: { ...df, ...custom?.features },
    app: {
      ...mergedAppBase,
      releaseVersion: mergedAppBase.releaseVersion ?? defaultReleaseVersionFromEnv(),
    },
    styling: stylingSchema.parse({
      classPrefix: custom?.styling?.classPrefix ?? defaultWidgetInitConfig.styling!.classPrefix,
    }),
  });
}

/**
 * Helper to apply theme preset
 */
export function applyThemePreset(
  preset: keyof typeof themePresets,
  custom?: DeepPartialWidgetConfig
): WidgetInitConfig {
  const basePreset = themePresets[preset];
  return mergeConfig({
    ...custom,
    colors: {
      ...basePreset.colors,
      ...custom?.colors,
      text: { ...basePreset.colors.text, ...custom?.colors?.text },
      status: { ...defaultWidgetInitConfig.colors!.status, ...custom?.colors?.status }
    } as DeepPartialWidgetConfig['colors']
  });
}

/** UI shell fallbacks when optional `WidgetInitConfig` sections are absent (same as `defaultWidgetInitConfig`). */
export function resolveWidgetShellSections(config: WidgetInitConfig): {
  interactions: NonNullable<WidgetInitConfig['interactions']>;
  spacing: NonNullable<WidgetInitConfig['spacing']>;
  launcher: NonNullable<WidgetInitConfig['launcher']>;
  typography: NonNullable<WidgetInitConfig['typography']>;
  colors: NonNullable<WidgetInitConfig['colors']>;
  uiElements: NonNullable<WidgetInitConfig['uiElements']>;
  styling: NonNullable<WidgetInitConfig['styling']>;
} {
  const d = defaultWidgetInitConfig;
  return {
    interactions: config.interactions ?? d.interactions!,
    spacing: config.spacing ?? d.spacing!,
    launcher: config.launcher ?? d.launcher!,
    typography: config.typography ?? d.typography!,
    colors: config.colors ?? d.colors!,
    uiElements: config.uiElements ?? d.uiElements!,
    styling: config.styling ?? d.styling!,
  };
}
