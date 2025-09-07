/**
 * Flipper Zero Integration Types
 * Shared types and interfaces for cross-platform Flipper Zero support
 */

export type TransportKind = 'usb' | 'ble' | 'bridge';

export interface Transport {
  id: string;
  kind: TransportKind;
  open(): Promise<void>;
  close(): Promise<void>;
  write(line: string | Uint8Array): Promise<void>;
  onLine(cb: (line: string) => void): () => void; // returns unsubscribe function
}

export interface Session {
  id: string;
  transport: Transport;
  rpc: FlipperRPC;
  createdAt: number;
}

export interface FlipperRPC {
  info(): Promise<string[]>;
  fsList(path?: string): Promise<string[]>;
  fsRead(path: string): Promise<string[]>;
  fsWriteBegin(path: string, length: number): Promise<string[]>;
  fsWriteData(data: string | Uint8Array): Promise<string[]>;
  fsWriteEnd(): Promise<string[]>;
  fsDelete(path: string): Promise<string[]>;
  irSend(file: string): Promise<string[]>;
  subghzTx(file: string): Promise<string[]>;
  nfcRead(): Promise<string[]>;
  nfcDump(): Promise<string[]>;
  rfidRead(): Promise<string[]>;
  rfidDump(): Promise<string[]>;
  badusbSend(script: string): Promise<string[]>;
  uartSniff(duration?: number): Promise<string[]>;
  gpioSet(pin: number, value: boolean): Promise<string[]>;
  gpioRead(pin: number): Promise<string[]>;
  bleScan(duration?: number): Promise<string[]>;
  blePair(address: string): Promise<string[]>;
}

export interface FlipperDevice {
  id: string;
  name: string;
  transport: TransportKind;
  path?: string; // For USB devices
  address?: string; // For BLE devices
  bridgeUrl?: string; // For bridge devices
  connected: boolean;
}

export interface FlipperOperationResult {
  success: boolean;
  data?: any;
  error?: string;
  sessionId?: string;
}

export interface FlipperAuditLog {
  timestamp: number;
  action: string;
  sessionId: string;
  deviceId: string;
  payload?: {
    length?: number;
    hash?: string;
    type?: string;
  };
  metadata?: Record<string, unknown>;
}

// Environment configuration interface
export interface FlipperConfig {
  enabled: boolean;
  usbEnabled: boolean;
  bleEnabled: boolean;
  allowTx: boolean;
  txMaxSeconds: number;
  logStreams: boolean;
  bridgeUrl?: string;
}

// Error types
export class FlipperError extends Error {
  constructor(
    message: string,
    public code: string,
    public sessionId?: string
  ) {
    super(message);
    this.name = 'FlipperError';
  }
}

export class FlipperTransportError extends FlipperError {
  constructor(message: string, sessionId?: string) {
    super(message, 'TRANSPORT_ERROR', sessionId);
    this.name = 'FlipperTransportError';
  }
}

export class FlipperRPCError extends FlipperError {
  constructor(message: string, sessionId?: string) {
    super(message, 'RPC_ERROR', sessionId);
    this.name = 'FlipperRPCError';
  }
}

export class FlipperSecurityError extends FlipperError {
  constructor(message: string, sessionId?: string) {
    super(message, 'SECURITY_ERROR', sessionId);
    this.name = 'FlipperSecurityError';
  }
}
