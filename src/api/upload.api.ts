import { API_PATHS } from '../constants/api.constant';
import { ApiError } from '../lib/api-error';
import { apiService } from '../lib/api-service';
import type { UploadFileResult } from '../types/chat';

export type PresignedUploadPayload = {
  method: string;
  uploadUrl: string;
  fileUrl: string;
  key: string;
  headers: Record<string, string>;
  expiresIn: number;
};

function basenameFileName(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) {
    return 'upload.bin';
  }
  const parts = trimmed.split(/[/\\]/);
  return parts[parts.length - 1] || 'upload.bin';
}

async function putToPresignedUrl(
  uploadUrl: string,
  method: string,
  headers: Record<string, string> | undefined,
  body: Blob
): Promise<void> {
  const verb = (method || 'PUT').toUpperCase();
  const h = new Headers();
  if (headers && typeof headers === 'object') {
    for (const [key, value] of Object.entries(headers)) {
      if (value != null && value !== '') {
        h.set(key, String(value));
      }
    }
  }
  const res = await fetch(uploadUrl, { method: verb, headers: h, body });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new ApiError(
      detail.trim() || `Storage upload failed (${res.status})`,
      res.status
    );
  }
}

export type UploadFileOptions = {
  /** Optional extra path segment under tenant folder (`api_doc.md`). */
  prefix?: string;
};

/**
 * Vitafy flow: `POST /api/upload` (JSON) → `PUT uploadUrl` with file bytes → use `fileUrl` in chat `attachments[].url`.
 */
export const uploadFileRequest = async (
  file: File | Blob,
  options?: UploadFileOptions & { fileName?: string; mimeType?: string }
): Promise<UploadFileResult> => {
  const fileName =
    basenameFileName(
      options?.fileName ?? (file instanceof File ? file.name : 'upload.bin')
    );
  const mimeType =
    options?.mimeType ||
    (file instanceof File && file.type ? file.type : 'application/octet-stream');
  const byteSize = file.size;

  const presign = await apiService.post<PresignedUploadPayload>(API_PATHS.UPLOAD, {
    fileName,
    mimeType,
    byteSize,
    ...(options?.prefix ? { prefix: options.prefix } : {})
  });

  await putToPresignedUrl(presign.uploadUrl, presign.method, presign.headers, file);

  return {
    fileUrl: presign.fileUrl,
    key: presign.key,
    mimeType,
    byteSize
  };
};
