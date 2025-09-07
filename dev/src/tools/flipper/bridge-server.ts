/**
 * Flipper Bridge Server (WebSocket)
 * Runs on a desktop OS with USB/BLE access and relays line-oriented RPC
 * to clients over WebSocket. Intended as a cross-platform fallback for
 * Android/iOS where direct transports are unavailable.
 */

import { WebSocketServer } from 'ws';
import { usbTransport, findFlipperUsbDevices, testUsbConnection } from './transport/usbSerial.js';
import { bleTransport, scanForFlipperDevices, testBleConnection, isBleAvailable } from './transport/ble.js';

const PORT = Number(process.env.MCPGM_FLIPPER_BRIDGE_PORT ?? 9910);

type Session = {
  transport: ReturnType<typeof usbTransport> | ReturnType<typeof bleTransport> | null;
  unsubscribe?: () => void;
};

const wss = new WebSocketServer({ port: PORT });
console.log(`[Flipper Bridge] Listening on ws://localhost:${PORT}`);

wss.on('connection', (ws) => {
  const session: Session = { transport: null };

  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      switch (msg.type) {
        case 'open': {
          // msg.deviceId like 'usb:COM5' or 'ble:peripheralId'
          const [kind, id] = String(msg.deviceId || '').split(':');
          if (!kind || !id) return ws.send(JSON.stringify({ type: 'error', error: 'invalid_deviceId' }));
          if (session.transport) await session.transport.close();
          session.transport = kind === 'usb' ? usbTransport(id) : bleTransport(id);
          await session.transport.open();
          session.unsubscribe = session.transport.onLine((line) => {
            try { ws.send(JSON.stringify({ type: 'line', data: line })); } catch {}
          });
          return ws.send(JSON.stringify({ type: 'ok', event: 'open' }));
        }
        case 'write': {
          if (!session.transport) return;
          await session.transport.write(String(msg.data ?? ''));
          return;
        }
        case 'write_base64': {
          if (!session.transport) return;
          const buf = Buffer.from(String(msg.data ?? ''), 'base64');
          await session.transport.write(buf);
          return;
        }
        case 'close': {
          if (session.unsubscribe) try { session.unsubscribe(); } catch {}
          if (session.transport) try { await session.transport.close(); } catch {}
          session.unsubscribe = undefined;
          session.transport = null;
          return ws.send(JSON.stringify({ type: 'ok', event: 'close' }));
        }
        case 'list_devices': {
          const usb = await findFlipperUsbDevices();
          const bleOk = await isBleAvailable();
          const ble = bleOk ? await scanForFlipperDevices(3500) : [];
          return ws.send(JSON.stringify({ type: 'devices', usb, ble }));
        }
        case 'probe': {
          return ws.send(JSON.stringify({ type: 'pong', bridge: true }));
        }
        default:
          return;
      }
    } catch {
      // ignore
    }
  });

  ws.on('close', async () => {
    try { session.unsubscribe?.(); } catch {}
    try { await session.transport?.close(); } catch {}
  });
});

