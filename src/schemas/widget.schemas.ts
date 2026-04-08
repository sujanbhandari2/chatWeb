import { z } from 'zod';

/**
 * Color palette schema for comprehensive theming
 */
const colorPaletteSchema = z.object({
  primary: z.string().default('#2563eb'),
  secondary: z.string().default('#64748b'),
  accent: z.string().default('#f59e0b'),
  background: z.string().default('#ffffff'),
  surface: z.string().default('#f8fafc'),
  border: z.string().default('#e2e8f0'),
  text: z.object({
    primary: z.string().default('#1e293b'),
    secondary: z.string().default('#64748b'),
    tertiary: z.string().default('#94a3b8'),
    inverse: z.string().default('#ffffff'),
  }),
  status: z.object({
    success: z.string().default('#10b981'),
    error: z.string().default('#ef4444'),
    warning: z.string().default('#f59e0b'),
    info: z.string().default('#0ea5e9'),
  }),
});

/**
 * Typography schema for consistent font styling
 */
const typographySchema = z.object({
  fontFamily: z.string().default('Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
  fontSize: z.object({
    xs: z.number().positive().default(12),
    sm: z.number().positive().default(14),
    base: z.number().positive().default(16),
    lg: z.number().positive().default(18),
    xl: z.number().positive().default(20),
    '2xl': z.number().positive().default(24),
  }),
  fontWeight: z.object({
    light: z.number().default(300),
    normal: z.number().default(400),
    medium: z.number().default(500),
    semibold: z.number().default(600),
    bold: z.number().default(700),
  }),
  lineHeight: z.number().positive().default(1.5),
  letterSpacing: z.number().default(0),
});

/**
 * Spacing and sizing schema
 */
const spacingSchema = z.object({
  offsetBottom: z.number().nonnegative().default(24),
  offsetSide: z.number().nonnegative().default(24),
  launcherSize: z.number().positive().default(56),
  panelWidth: z.number().positive().default(380),
  panelHeight: z.number().positive().default(560),
  panelMaxWidth: z.string().optional(),
  panelMaxHeight: z.string().optional(),
  panelBorderRadius: z.string().default('12px'),
  panelBoxShadow: z.string().default('0 12px 40px rgba(15, 23, 42, 0.15)'),
});

/**
 * Launcher (floating button) schema
 */
const launcherSchema = z.object({
  size: z.number().positive().default(56),
  iconUrl: z.string().optional(),
  ariaLabel: z.string().default('Open chat'),
  position: z.enum(['left', 'right', 'bottom-left', 'bottom-right']).default('right'),
  badge: z.object({
    enabled: z.boolean().default(false),
    backgroundColor: z.string().default('#ef4444'),
    textColor: z.string().default('#ffffff'),
    count: z.number().nonnegative().optional(),
  }).optional(),
});

/**
 * Animation and interaction schema
 */
const interactionSchema = z.object({
  closeOnEscape: z.boolean().default(true),
  closeOnClickOutside: z.boolean().default(true),
  defaultOpen: z.boolean().default(false),
  animationEnabled: z.boolean().default(true),
  animationDuration: z.number().nonnegative().default(300),
});

/**
 * Header and UI elements schema
 */
const uiElementsSchema = z.object({
  panelTitle: z.string().optional(),
  showHeader: z.boolean().default(true),
  showFooter: z.boolean().default(true),
  showBranding: z.boolean().default(false),
  brandingText: z.string().optional(),
  headerIconUrl: z.string().optional(),
});

/**
 * Tenant and API configuration schema
 */
const backendSchema = z.object({
  tenantId: z.string().optional(),
  lockTenant: z.boolean().default(false),
  hideTenantField: z.boolean().default(false),
  apiUrl: z.string().optional(),
  socketUrl: z.string().optional(),
  apiTimeout: z.number().positive().default(30000),
  retryAttempts: z.number().nonnegative().default(3),
});

/**
 * Accessibility schema
 */
const a11ySchema = z.object({
  ariaLabel: z.string().default('Chat widget'),
  ariaDescribedBy: z.string().optional(),
  reduceMotion: z.boolean().default(false),
  highContrast: z.boolean().default(false),
});

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
    defaultOpen: false,
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

export function mergeConfig(custom?: DeepPartialWidgetConfig): WidgetInitConfig {
  const dc = defaultWidgetInitConfig.colors!;
  const dt = defaultWidgetInitConfig.typography!;
  const dl = defaultWidgetInitConfig.launcher!;
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
    a11y: { ...defaultWidgetInitConfig.a11y, ...custom?.a11y }
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
