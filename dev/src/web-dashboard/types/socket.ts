import { Socket } from 'socket.io-client';

export interface SocketContextType {
  socket: Socket | null;
  connect: () => void;
  disconnect: () => void;
}
