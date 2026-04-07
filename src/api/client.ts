import type { LoginInput, RegisterInput } from '../schemas/auth';
import type {
  Conversation,
  CreateAccountResponse,
  HealthResponse,
  Message,
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
export async function createAccount(input: RegisterInput): Promise<CreateAccountResponse> {
  return requestJson<CreateAccountResponse>('/auth/create', {
    method: 'POST',
    body: JSON.stringify(input)
  });
}

/** POST /api/auth/login */
export async function login(input: LoginInput): Promise<CreateAccountResponse> {
  return requestJson<CreateAccountResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(input)
  });
}

/** POST /api/conversations */
export async function createConversation(token: string, participantIds: string[]): Promise<Conversation> {
  return requestJson<Conversation>('/conversations', {
    method: 'POST',
    token,
    body: JSON.stringify({ participantIds })
  });
}

/** POST /api/conversations/direct */
export async function createDirectConversation(token: string, userId: string): Promise<Conversation> {
  return requestJson<Conversation>('/conversations/direct', {
    method: 'POST',
    token,
    body: JSON.stringify({ userId })
  });
}

/** POST /api/conversations/group */
export async function createGroupConversation(
  token: string,
  title: string,
  participantIds: string[]
): Promise<Conversation> {
  return requestJson<Conversation>('/conversations/group', {
    method: 'POST',
    token,
    body: JSON.stringify({ title, participantIds })
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

/** DELETE /api/conversations/:id — remove conversation for current user / delete group (server-defined). */
export async function deleteConversation(token: string, conversationId: string): Promise<void> {
  await requestJson<void>(`/conversations/${conversationId}`, {
    method: 'DELETE',
    token
  });
}

/** PATCH /api/conversations/:id — update metadata (e.g. group title). */
export async function updateConversation(
  token: string,
  conversationId: string,
  body: { title: string }
): Promise<Conversation> {
  return requestJson<Conversation>(`/conversations/${conversationId}`, {
    method: 'PATCH',
    token,
    body: JSON.stringify(body)
  });
}

/** POST /api/conversations/:id/participants — add users to a group. */
export async function addConversationParticipants(
  token: string,
  conversationId: string,
  userIds: string[]
): Promise<Conversation> {
  return requestJson<Conversation>(`/conversations/${conversationId}/participants`, {
    method: 'POST',
    token,
    body: JSON.stringify({ userIds })
  });
}

/** DELETE /api/conversations/:id/participants/:userId — remove a member (or leave). */
export async function removeConversationParticipant(
  token: string,
  conversationId: string,
  userId: string
): Promise<void> {
  await requestJson<void>(`/conversations/${conversationId}/participants/${userId}`, {
    method: 'DELETE',
    token
  });
}

/** GET /api/conversations/:id/messages */
export async function getMessages(
  token: string,
  conversationId: string,
  page = 1,
  pageSize = 50
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

/**
 * POST /api/conversations/:conversationId/messages/:messageId/reactions
 * Persists a reaction when the API supports it. Returns the updated message when possible.
 */
export async function addMessageReaction(
  token: string,
  conversationId: string,
  messageId: string,
  emoji: string
): Promise<Message> {
  const raw = await requestJson<Message | { data: Message }>(
    `/conversations/${conversationId}/messages/${messageId}/reactions`,
    {
      method: 'POST',
      token,
      body: JSON.stringify({ emoji, reactionType: emoji })
    }
  );
  if (raw && typeof raw === 'object' && 'data' in raw && raw.data && typeof (raw as { data: Message }).data.id === 'string') {
    return (raw as { data: Message }).data;
  }
  return raw as Message;
}

/** GET /api/users */
export async function getUsers(token: string): Promise<TenantUser[]> {
  const response = await requestJson<{ data: TenantUser[] }>('/users', {
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

/** POST /api/speech/transcribe */
export async function transcribeSpeech(
  token: string,
  audio: File | Blob,
  options?: { language?: string; processAgain?: boolean; filename?: string }
): Promise<TranscribeResponse> {
  const formData = new FormData();
  const name = options?.filename ?? (audio instanceof File ? audio.name : 'audio.webm');
  formData.append('audio', audio, name);
  if (options?.language) {
    formData.append('language', options.language);
  }
  if (options?.processAgain !== undefined) {
    formData.append('processAgain', options.processAgain ? 'true' : 'false');
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

/** POST /api/speech/translate */
export async function translateText(
  token: string,
  input: { text: string; targetLanguage: string; sourceLanguage?: string }
): Promise<TranslateResponse> {
  return requestJson<TranslateResponse>('/speech/translate', {
    method: 'POST',
    token,
    body: JSON.stringify(input)
  });
}

export { API_BASE as apiBaseUrl, SERVER_ORIGIN as serverOrigin };
