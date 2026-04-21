import type { Socket } from 'socket.io-client';
import { SOCKET_ACK_TIMEOUT_MS } from '../features/chat/chat.constants';

type SocketAckEnvelope<T> = { ok: boolean; data?: T; error?: string };

let activeSocket: Socket | null = null;

export function setChatSocketInstance(socket: Socket | null): void {
  activeSocket = socket;
}

export function getChatSocket(): Socket | null {
  return activeSocket;
}

function isAckEnvelope(value: unknown): value is SocketAckEnvelope<unknown> {
  return Boolean(value && typeof value === 'object' && 'ok' in value);
}

/**
 * Vitafy `send_message` ack returns the created message directly; `join_conversation` returns `{ ok: true }`.
 */
export async function chatEmitWithAck<T>(event: string, payload: unknown): Promise<T> {
  const socket = activeSocket;
  if (!socket) {
    throw new Error('Socket is not connected');
  }

  return new Promise<T>((resolve, reject) => {
    const timeoutId = window.setTimeout(() => {
      reject(new Error(`Socket event timeout: ${event}`));
    }, SOCKET_ACK_TIMEOUT_MS);

    socket.emit(event, payload, (response: unknown) => {
      window.clearTimeout(timeoutId);

      if (isAckEnvelope(response)) {
        if (response.ok === false) {
          reject(new Error(response.error ?? 'Socket error'));
          return;
        }
        if (response.ok === true && 'data' in response && response.data !== undefined) {
          resolve(response.data as T);
          return;
        }
        resolve(response as T);
        return;
      }

      resolve(response as T);
    });
  });
}
