let runtimeApiUrl: string | undefined;
let runtimeSocketUrl: string | undefined;

/** Call before first API/socket use when embedding (e.g. from widget init config). */
export function applyRuntimeApiOverrides(overrides: { apiUrl?: string; socketUrl?: string }): void {
  runtimeApiUrl = overrides.apiUrl?.replace(/\/$/, '') || undefined;
  runtimeSocketUrl = overrides.socketUrl?.replace(/\/$/, '') || undefined;
}

function getApiConfig(): { origin: string; apiBase: string } {
  const raw = (
    runtimeApiUrl ??
    import.meta.env.VITE_API_URL ??
    'http://localhost:4000/api'
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
  return runtimeSocketUrl ?? import.meta.env.VITE_SOCKET_URL ?? 'http://localhost:4000';
}
