Flipper Zero Cross‑Platform Support
==================================

Overview
- Desktop (Windows/macOS/Linux): Uses USB (serial) and BLE via optional deps.
- Mobile (Android/iOS): Uses a WebSocket bridge to a desktop that has USB/BLE access.

Environment Flags
- `MCPGM_FLIPPER_ENABLED`: Set `true` to enable Flipper tools.
- `MCPGM_FLIPPER_USB_ENABLED`: Enable USB serial transport on desktop.
- `MCPGM_FLIPPER_BLE_ENABLED`: Enable BLE transport on desktop.
- `MCPGM_FLIPPER_ALLOW_TX`: Allow IR/Sub‑GHz/BadUSB transmissions (default `false`).
- `MCPGM_FLIPPER_TX_MAX_SECONDS`: Transmission cap in seconds (default `10`).
- `MCPGM_FLIPPER_LOG_STREAMS`: Stream raw line logs for auditing (default `false`).
- `MCPGM_FLIPPER_BRIDGE_URL`: WebSocket URL to a running bridge (for Android/iOS).

Bridge Transport (Android/iOS)
1) Start the bridge on a desktop with USB/BLE:
   - `node dev/dist/tools/flipper/bridge-server.js`
   - Optional: set `MCPGM_FLIPPER_BRIDGE_PORT` (default `9910`).
2) On the device where the MCP server runs (Android/iOS), set:
   - `MCPGM_FLIPPER_BRIDGE_URL=ws://<desktop-hostname>:9910`
3) Use `flipper_list_devices` – it will include a virtual device:
   - `id: bridge:ws://<desktop-hostname>:9910`
4) `flipper_connect` with that device ID to open a session via the bridge.

Notes
- All Flipper tools remain available; transport choice is transparent to RPC layer.
- Desktop transports are dynamically imported; if the module is unavailable, it is skipped gracefully.
- Bridge protocol is line‑oriented and relays tool RPC messages.

Security
- Keep bridge usage to trusted networks only; no authentication is enabled by default.
- Consider using a tunnel (SSH/ZeroTier/WireGuard) if exposing over untrusted links.

