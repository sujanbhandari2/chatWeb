import {
  mergeConfig,
  applyThemePreset,
  widgetInitConfigSchema,
  type WidgetInitConfig,
  type DeepPartialWidgetConfig
} from '../schemas/widget.schemas';


export const exampleCustomConfig: WidgetInitConfig = mergeConfig({
  colors: {
    primary: '#6366f1',
    secondary: '#06b6d4',
    accent: '#f97316'
  },
  spacing: {
    launcherSize: 64,
    panelWidth: 420,
    panelHeight: 600
  },
  launcher: {
    position: 'left',
    badge: {
      enabled: true,
      backgroundColor: '#ef4444',
      textColor: '#ffffff',
      count: 3
    }
  }
});


export const exampleDarkConfig: WidgetInitConfig = applyThemePreset('dark', {
  spacing: {
    launcherSize: 60
  }
});


export const exampleBrandConfig: WidgetInitConfig = applyThemePreset('brand', {
  uiElements: {
    showHeader: true,
    showFooter: true,
    panelTitle: 'Welcome to our support',
    showBranding: true,
    brandingText: 'Powered by VSuite'
  },
  launcher: {
    position: 'bottom-right',
    badge: {
      enabled: true,
      backgroundColor: '#ec4899',
      textColor: '#ffffff'
    }
  }
});

/**
 * Example 4: Fully specified widget config (validated against schema).
 * Use: `VITE_WIDGET_PROFILE=full`
 */
export const exampleFullConfig: WidgetInitConfig = widgetInitConfigSchema.parse({
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
      inverse: '#ffffff'
    },
    status: {
      success: '#10b981',
      error: '#ef4444',
      warning: '#f59e0b',
      info: '#0ea5e9'
    }
  },
  typography: {
    fontFamily: '"Segoe UI", Tahoma, Geneva, Verdana, sans-serif',
    fontSize: {
      xs: 12,
      sm: 14,
      base: 16,
      lg: 18,
      xl: 20,
      '2xl': 24
    },
    fontWeight: {
      light: 300,
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700
    },
    lineHeight: 1.6,
    letterSpacing: 0.5
  },
  spacing: {
    offsetBottom: 32,
    offsetSide: 32,
    launcherSize: 60,
    panelWidth: 400,
    panelHeight: 600,
    panelBorderRadius: '16px',
    panelBoxShadow: '0 20px 50px rgba(0, 0, 0, 0.2)'
  },
  launcher: {
    size: 60,
    iconUrl: '/assets/chat-icon.svg',
    ariaLabel: 'Open support chat',
    position: 'bottom-right',
    badge: {
      enabled: true,
      backgroundColor: '#ef4444',
      textColor: '#ffffff',
      count: 2
    }
  },
  interactions: {
    closeOnEscape: true,
    closeOnClickOutside: true,
    defaultOpen: false,
    animationEnabled: true,
    animationDuration: 400
  },
  uiElements: {
    panelTitle: 'Chat with us',
    showHeader: true,
    showFooter: true,
    showBranding: true,
    brandingText: 'Powered by WidgetChat',
    headerIconUrl: '/assets/logo.svg'
  },
  backend: {
    tenantId: 'my-company',
    lockTenant: false,
    hideTenantField: false,
    apiUrl: 'https://api.example.com',
    socketUrl: 'wss://socket.example.com',
    apiTimeout: 30000,
    retryAttempts: 3
  },
  a11y: {
    ariaLabel: 'Chat widget',
    ariaDescribedBy: 'chat-help-text',
    reduceMotion: false,
    highContrast: false
  },
  zIndex: 99999,
  debug: false
});

/** Named examples for demos, imports, or `VITE_WIDGET_PROFILE`. */
export const widgetConfigExamples = {
  custom: exampleCustomConfig,
  dark: exampleDarkConfig,
  brand: exampleBrandConfig,
  full: exampleFullConfig
} as const;

export type WidgetConfigExampleKey = keyof typeof widgetConfigExamples;

/**
 * Environment profiles (URLs, branding) merged before window / URL overrides in `getWidgetInitConfig()`.
 */
export const configs = {
  development: mergeConfig({
    debug: true,
  }),

  staging: applyThemePreset('light', {
  }),

  production: applyThemePreset('light', {
    uiElements: {
      showHeader: true,
      showFooter: true,
      showBranding: true,
      brandingText: 'Customer Support'
    }
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

/**
 * Env-based defaults for the widget bundle (before `window.__HEALTHCHAT_WIDGET_CONFIG__` and URL query).
 *
 * - **Profiles:** `VITE_WIDGET_PROFILE` or `import.meta.env.MODE`: `development` | `staging` | `production`
 * - **Examples:** `VITE_WIDGET_PROFILE=custom` | `dark` | `brand` | `full` uses the matching export from
 *   `widgetConfigExamples` (see `exampleCustomConfig`, etc.).
 */
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

/**
 * Apply config to `document.documentElement` as CSS variables (optional host-page helper).
 * For the same merge order as the widget bundle, use `getWidgetInitConfig()` from `widget-runtime.utils`.
 */
export function initializeWidget(customConfig?: DeepPartialWidgetConfig): WidgetInitConfig {
  const config = mergeConfig(customConfig);

  const root = document.documentElement;
  if (config.colors) {
    root.style.setProperty('--widget-primary', config.colors.primary);
    root.style.setProperty('--widget-secondary', config.colors.secondary);
    root.style.setProperty('--widget-accent', config.colors.accent);
    root.style.setProperty('--widget-background', config.colors.background);
    root.style.setProperty('--widget-text-primary', config.colors.text?.primary ?? '#000');
    root.style.setProperty('--widget-text-secondary', config.colors.text?.secondary ?? '#666');

    if (config.colors.status) {
      root.style.setProperty('--widget-success', config.colors.status.success);
      root.style.setProperty('--widget-error', config.colors.status.error);
      root.style.setProperty('--widget-warning', config.colors.status.warning);
      root.style.setProperty('--widget-info', config.colors.status.info);
    }
  }

  if (config.typography) {
    root.style.setProperty('--widget-font-family', config.typography.fontFamily);
    root.style.setProperty('--widget-font-size-base', `${config.typography.fontSize?.base ?? 16}px`);
    root.style.setProperty('--widget-line-height', `${config.typography.lineHeight}`);
  }

  if (config.spacing) {
    root.style.setProperty('--widget-panel-width', `${config.spacing.panelWidth}px`);
    root.style.setProperty('--widget-panel-height', `${config.spacing.panelHeight}px`);
    root.style.setProperty('--widget-launcher-size', `${config.spacing.launcherSize}px`);
    root.style.setProperty('--widget-panel-radius', config.spacing.panelBorderRadius);
  }

  return config;
}
