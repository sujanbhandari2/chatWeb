import { Conversation, LoginResponse, Message, TenantUser } from '../types/chat';

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:4000/api';

const request = async <T>(path: string, options: RequestInit = {}): Promise<T> => {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers ?? {})
    }
  });

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(errorPayload.message ?? 'Request failed');
  }

  return response.json() as Promise<T>;
};

export const register = async (input: {
  username: string;
  password: string;
}): Promise<LoginResponse> => {
  return request<LoginResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(input)
  });
};

export const login = async (input: {
  username: string;
  password: string;
}): Promise<LoginResponse> => {
  return request<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(input)
  });
};

export const getConversations = async (token: string): Promise<Conversation[]> => {
  const response = await request<{ data: Conversation[] }>('/conversations', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return response.data;
};

export const createConversation = async (
  token: string,
  participantIds: string[]
): Promise<Conversation> => {
  return request<Conversation>('/conversations', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({ participantIds })
  });
};

export const getUsers = async (token: string): Promise<TenantUser[]> => {
  const response = await request<{ data: TenantUser[] }>('/users', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return response.data;
};

export const getMessages = async (
  token: string,
  conversationId: string,
  page = 1,
  pageSize = 50
): Promise<Message[]> => {
  const response = await request<{ data: Message[] }>(
    `/conversations/${conversationId}/messages?page=${page}&pageSize=${pageSize}`,
    {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );

  return response.data;
};

export const uploadFile = async (token: string, file: File): Promise<{ url: string }> => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/upload`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`
    },
    body: formData
  });

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({ message: 'Upload failed' }));
    throw new Error(errorPayload.message ?? 'Upload failed');
  }

  return response.json() as Promise<{ url: string }>;
};
