import axios from 'axios';
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
  const { data } = await axios.get<Blob>(absolute, {
    responseType: 'blob',
    headers: token ? { Authorization: `Bearer ${token}` } : undefined
  });
  return data;
}
