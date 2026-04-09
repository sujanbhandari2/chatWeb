import type { Socket } from 'socket.io-client';
import { SOCKET_ACK_TIMEOUT_MS } from '../features/chat/chat.constants';

type SocketAck<T> = { ok: boolean; data?: T; error?: string };

let activeSocket: Socket | null = null;

export function setChatSocketInstance(socket: Socket | null): void {
  activeSocket = socket;
}

export function getChatSocket(): Socket | null {
  return activeSocket;
}

export async function chatEmitWithAck<T>(event: string, payload: unknown): Promise<T> {
  const socket = activeSocket;
  if (!socket) {
    throw new Error('Socket is not connected');
  }

  return new Promise<T>((resolve, reject) => {
    const timeoutId = window.setTimeout(() => {
      reject(new Error(`Socket event timeout: ${event}`));
    }, SOCKET_ACK_TIMEOUT_MS);

    socket.emit(event, payload, (response: SocketAck<T>) => {
      window.clearTimeout(timeoutId);

      if (!response.ok) {
        reject(new Error(response.error ?? 'Socket error'));
        return;
      }

      resolve(response.data as T);
    });
  });
}
