import axios from 'axios';
import { getResolvedApiKey, resolveEffectiveXCompanyId } from '../lib/api-credentials';
import { formatWireXApiKeyValue } from './chat-api-key.utils';
import { getServerOrigin } from './runtime-endpoints.utils';

export function toAbsoluteMediaUrl(url: string): string {
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return url;
  }
  return `${getServerOrigin()}${url}`;
}

/** GET binary/media with optional auth (used for transcribing attachment URLs). */
export async function fetchMediaBlob(url: string, token?: string): Promise<Blob> {
  const absolute = toAbsoluteMediaUrl(url);
  const headers: Record<string, string> = {};
  if (token?.trim()) {
    headers.Authorization = `Bearer ${token}`;
  } else {
    const key = formatWireXApiKeyValue(getResolvedApiKey());
    if (key) {
      headers['X-Api-Key'] = key;
    }
  }
  const companyId = resolveEffectiveXCompanyId(undefined);
  if (companyId) {
    headers['X-Company-Id'] = companyId;
  }
  const { data } = await axios.get<Blob>(absolute, {
    responseType: 'blob',
    ...(Object.keys(headers).length > 0 ? { headers } : {})
  });
  return data;
}
