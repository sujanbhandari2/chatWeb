let runtimeApiUrl: string | undefined;
let runtimeSocketUrl: string | undefined;
let runtimeApiTimeoutMs: number | undefined;

/** Call before first API/socket use when embedding (e.g. from `getWidgetInitConfig()` in `main-widget.tsx`). */
export function applyRuntimeApiOverrides(overrides: {
  apiUrl?: string;
  socketUrl?: string;
  /** From `WidgetInitConfig.backend.apiTimeout`; applied to axios request `timeout`. */
  apiTimeout?: number;
}): void {
  runtimeApiUrl = overrides.apiUrl?.replace(/\/$/, '') || undefined;
  runtimeSocketUrl = overrides.socketUrl?.replace(/\/$/, '') || undefined;
  if (overrides.apiTimeout !== undefined && Number.isFinite(overrides.apiTimeout) && overrides.apiTimeout > 0) {
    runtimeApiTimeoutMs = overrides.apiTimeout;
  }
}

/** Resolved API request timeout (ms) when the widget set `backend.apiTimeout`; otherwise unset. */
export function getResolvedApiTimeoutMs(): number | undefined {
  return runtimeApiTimeoutMs;
}

function getApiConfig(): { origin: string; apiBase: string } {
  const raw = (
    runtimeApiUrl ??
    import.meta.env.VITE_API_URL ??
    'http://localhost:4040/api'
  ).replace(/\/$/, '');
  if (raw.endsWith('/api')) {
    return { origin: raw.replace(/\/api$/, ''), apiBase: raw };
  }
  return { origin: raw, apiBase: `${raw}/api` };
}

export function getServerOrigin(): string {
  return getApiConfig().origin;
}

export function getApiBaseUrl(): string {
  return getApiConfig().apiBase;
}

export function getResolvedSocketUrl(): string {
  if (runtimeSocketUrl) {
    return runtimeSocketUrl;
  }
  const fromEnv = import.meta.env.VITE_SOCKET_URL;
  if (typeof fromEnv === 'string' && fromEnv.trim()) {
    return fromEnv.replace(/\/$/, '');
  }
  /** Same HTTP origin as REST so a correct `VITE_API_URL` alone cannot leave sockets on the wrong port/host. */
  return getServerOrigin();
}
