import type { Socket } from 'socket.io-client';
import { SOCKET_ACK_TIMEOUT_MS } from '../features/chat/chat.constants';

export type ChatEmitWithAckOptions = {
  timeoutMs?: number;
};

type LegacySocketAck<T> = { ok: boolean; data?: T; error?: string };

let activeSocket: Socket | null = null;

/** Backend may ack with a bare payload (e.g. `ChatMessage`) or legacy `{ ok, data?, error? }`. */
export function unwrapSocketAck<T>(response: unknown): T {
  if (response instanceof Error) {
    throw response;
  }
  if (typeof response === 'string') {
    throw new Error(response);
  }
  if (response && typeof response === 'object' && 'ok' in response) {
    const r = response as LegacySocketAck<T>;
    if (r.ok === false) {
      throw new Error(r.error ?? 'Socket error');
    }
    if (r.data !== undefined) {
      return r.data as T;
    }
    return response as T;
  }
  return response as T;
}

export function setChatSocketInstance(socket: Socket | null): void {
  activeSocket = socket;
}

export function getChatSocket(): Socket | null {
  return activeSocket;
}

export async function chatEmitWithAck<T>(
  event: string,
  payload: unknown,
  options?: ChatEmitWithAckOptions
): Promise<T> {
  const socket = activeSocket;
  if (!socket) {
    throw new Error('Socket is not connected');
  }

  const timeoutMs = options?.timeoutMs ?? SOCKET_ACK_TIMEOUT_MS;

  return new Promise<T>((resolve, reject) => {
    const timeoutId = window.setTimeout(() => {
      reject(new Error(`Socket event timeout: ${event}`));
    }, timeoutMs);

    socket.emit(event, payload, (response: unknown) => {
      window.clearTimeout(timeoutId);
      try {
        resolve(unwrapSocketAck<T>(response));
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  });
}
