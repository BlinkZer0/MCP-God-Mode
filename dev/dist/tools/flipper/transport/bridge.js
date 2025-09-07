/**
 * Flipper Zero Bridge Transport (WebSocket)
 * Enables cross-platform access via a remote bridge server.
 */
import { FlipperTransportError } from '../types.js';
export function bridgeTransport(url, sessionHint, openTarget) {
    let WebSocketImpl = null;
    let ws = null;
    let isOpen = false;
    const listeners = new Set();
    return {
        id: `bridge:${sessionHint || 'default'}`,
        kind: 'bridge',
        async open() {
            if (isOpen)
                throw new FlipperTransportError('Bridge transport already open');
            try {
                // Dynamic import to avoid hard dependency when unused
                const wsModule = await import('ws');
                WebSocketImpl = wsModule.WebSocket || wsModule.default || wsModule;
                if (!WebSocketImpl)
                    throw new Error('ws module not available');
                await new Promise((resolve, reject) => {
                    ws = new WebSocketImpl(url);
                    const timer = setTimeout(() => reject(new FlipperTransportError('Bridge connect timeout')), 8000);
                    ws.onopen = () => {
                        clearTimeout(timer);
                        isOpen = true;
                        try {
                            if (openTarget) {
                                ws.send(JSON.stringify({ type: 'open', deviceId: openTarget }));
                            }
                        }
                        catch { }
                        resolve();
                    };
                    ws.onerror = (err) => {
                        clearTimeout(timer);
                        reject(new FlipperTransportError(`Bridge error: ${err?.message || String(err)}`));
                    };
                    ws.onclose = () => {
                        isOpen = false;
                    };
                    ws.onmessage = (evt) => {
                        try {
                            const data = typeof evt.data === 'string' ? evt.data : evt.data?.toString?.('utf8');
                            if (!data)
                                return;
                            // Expect line-oriented messages or JSON with type: 'line'
                            if (data.startsWith('{') && data.includes('"type"')) {
                                const obj = JSON.parse(data);
                                if (obj.type === 'line' && typeof obj.data === 'string') {
                                    listeners.forEach(cb => cb(obj.data));
                                }
                            }
                            else {
                                const lines = String(data).split('\n');
                                for (const line of lines) {
                                    const trimmed = line.trim();
                                    if (trimmed)
                                        listeners.forEach(cb => cb(trimmed));
                                }
                            }
                        }
                        catch {
                            // Ignore malformed frames
                        }
                    };
                });
            }
            catch (error) {
                isOpen = false;
                throw new FlipperTransportError(`Bridge connection failed: ${error?.message || String(error)}`);
            }
        },
        async close() {
            if (!isOpen)
                return;
            try {
                listeners.clear();
                await new Promise((resolve) => {
                    try {
                        ws?.close?.();
                    }
                    catch { }
                    isOpen = false;
                    resolve();
                });
            }
            catch (error) {
                isOpen = false;
            }
        },
        async write(data) {
            if (!isOpen || !ws)
                throw new FlipperTransportError('Bridge transport not open');
            try {
                const payload = typeof data === 'string' ? data : Buffer.from(data).toString('base64');
                const frame = typeof data === 'string'
                    ? { type: 'write', data: payload }
                    : { type: 'write_base64', data: payload };
                ws.send(JSON.stringify(frame));
            }
            catch (error) {
                throw new FlipperTransportError(`Bridge write failed: ${error?.message || String(error)}`);
            }
        },
        onLine(cb) {
            listeners.add(cb);
            return () => listeners.delete(cb);
        }
    };
}
