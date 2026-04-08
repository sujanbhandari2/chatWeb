import { io, type Socket } from 'socket.io-client';
import { getResolvedSocketUrl } from '../utils/runtime-endpoints.utils';

export function createChatSocket(token: string): Socket {
  return io(getResolvedSocketUrl(), {
    auth: { token },
    transports: ['websocket']
  });
}
