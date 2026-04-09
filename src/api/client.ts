import type { CreateInTenantInput, LoginInput } from '../schemas/auth';
import type {
  Conversation,
  CreateAccountResponse,
  HealthResponse,
  MessagesPage,
  TenantUser,
  TranslateResponse,
  TranscribeResponse,
  UploadFileResponse
} from '../types/chat';

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function getApiConfig(): { origin: string; apiBase: string } {
  const raw = (import.meta.env.VITE_API_URL ?? 'http://localhost:4000/api').replace(/\/$/, '');
  if (raw.endsWith('/api')) {
    return { origin: raw.replace(/\/api$/, ''), apiBase: raw };
  }
  return { origin: raw, apiBase: `${raw}/api` };
}

const { origin: SERVER_ORIGIN, apiBase: API_BASE } = getApiConfig();

const jsonHeaders = (token?: string): HeadersInit => ({
  'Content-Type': 'application/json',
  ...(token ? { Authorization: `Bearer ${token}` } : {})
});

async function parseErrorBody(response: Response): Promise<{ message: string; details?: unknown; code?: string }> {
  const fallback = { message: response.statusText || 'Request failed' };
  try {
    const body = (await response.json()) as {
      message?: string;
      details?: unknown;
      code?: string;
    };
    return {
      message: typeof body.message === 'string' ? body.message : fallback.message,
      details: body.details,
      code: typeof body.code === 'string' ? body.code : undefined
    };
  } catch {
    return fallback;
  }
}

export async function requestJson<T>(
  path: string,
  options: RequestInit & { token?: string } = {}
): Promise<T> {
  const { token, headers: extraHeaders, ...rest } = options;
  const url = path.startsWith('http') ? path : `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;

  const response = await fetch(url, {
    ...rest,
    headers: {
      ...jsonHeaders(token),
      ...(extraHeaders ?? {})
    }
  });

  if (!response.ok) {
    const { message, details } = await parseErrorBody(response);
    throw new ApiError(message, response.status, details);
  }

  if (response.status === 204 || response.headers.get('content-length') === '0') {
    return undefined as T;
  }

  const text = await response.text();
  if (!text) {
    return undefined as T;
  }

  return JSON.parse(text) as T;
}

/** GET /health (server root, not under /api) */
export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch(`${SERVER_ORIGIN}/health`);
  if (!response.ok) {
    const { message, details } = await parseErrorBody(response);
    throw new ApiError(message, response.status, details);
  }
  return response.json() as Promise<HealthResponse>;
}

/** POST /api/auth/create */
export async function createAccount(input: CreateInTenantInput): Promise<CreateAccountResponse> {
  return requestJson<CreateAccountResponse>('/auth/create', {
    method: 'POST',
    body: JSON.stringify(input)
  });
}

/** POST /api/auth/login */
export async function login(input: LoginInput): Promise<CreateAccountResponse> {
  return requestJson<CreateAccountResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: input.email,
      tenantId: input.tenantId
    })
  });
}

/** POST /api/conversations — creator is always included; pass other participant ids only */
export async function createConversation(token: string, participantIds: string[]): Promise<Conversation> {
  return requestJson<Conversation>('/conversations', {
    method: 'POST',
    token,
    body: JSON.stringify({ participantIds })
  });
}

/** GET /api/conversations */
export async function getConversations(token: string): Promise<Conversation[]> {
  const response = await requestJson<{ data: Conversation[] }>('/conversations', {
    method: 'GET',
    token
  });
  return response.data;
}

/** GET /api/conversations/:id/messages */
export async function getMessages(
  token: string,
  conversationId: string,
  page = 1,
  pageSize = 20
): Promise<MessagesPage> {
  const query = new URLSearchParams({
    page: String(page),
    pageSize: String(pageSize)
  });
  return requestJson<MessagesPage>(`/conversations/${conversationId}/messages?${query.toString()}`, {
    method: 'GET',
    token
  });
}

/** GET /api/users */
export async function getUsers(token: string): Promise<TenantUser[]> {
  const response = await requestJson<{ data: TenantUser[] }>('/users/', {
    method: 'GET',
    token
  });
  return response.data;
}

/** POST /api/upload */
export async function uploadFile(token: string, file: File): Promise<UploadFileResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`
    },
    body: formData
  });

  if (!response.ok) {
    const { message, details } = await parseErrorBody(response);
    throw new ApiError(message, response.status, details);
  }

  return response.json() as Promise<UploadFileResponse>;
}

/** POST /api/speech/transcribe — multipart field `file` (≤25 MB); optional ISO-639-1 `language` */
export async function transcribeSpeech(
  token: string,
  audio: File | Blob,
  options?: { language?: string; filename?: string }
): Promise<TranscribeResponse> {
  const formData = new FormData();
  const name = options?.filename ?? (audio instanceof File ? audio.name : 'recording.webm');
  formData.append('file', audio, name);
  if (options?.language) {
    formData.append('language', options.language);
  }

  const response = await fetch(`${API_BASE}/speech/transcribe`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`
    },
    body: formData
  });

  if (!response.ok) {
    const { message, details } = await parseErrorBody(response);
    throw new ApiError(message, response.status, details);
  }

  return response.json() as Promise<TranscribeResponse>;
}

/** POST /api/speech/translate — JSON: text (1–50k), targetLanguage (2–80 chars, e.g. Spanish, ja) */
export async function translateText(
  token: string,
  input: { text: string; targetLanguage: string }
): Promise<TranslateResponse> {
  return requestJson<TranslateResponse>('/speech/translate', {
    method: 'POST',
    token,
    body: JSON.stringify({
      text: input.text,
      targetLanguage: input.targetLanguage
    })
  });
}

/** POST /api/users/push-token */
export async function registerPushToken(
  authToken: string,
  payload: { token: string; platform: 'IOS' | 'ANDROID' | 'WEB'; deviceId?: string }
): Promise<{ ok: boolean }> {
  return requestJson<{ ok: boolean }>('/users/push-token', {
    method: 'POST',
    token: authToken,
    body: JSON.stringify(payload)
  });
}

/** DELETE /api/users/push-token */
export async function deletePushToken(authToken: string, deviceToken: string): Promise<{ ok: boolean }> {
  return requestJson<{ ok: boolean }>('/users/push-token', {
    method: 'DELETE',
    token: authToken,
    body: JSON.stringify({ token: deviceToken })
  });
}

export { API_BASE as apiBaseUrl, SERVER_ORIGIN as serverOrigin };
