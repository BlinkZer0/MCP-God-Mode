# MCP God Mode - Version 1.7b Changelog

Release Date: September 2025  
Version: 1.7b  
Codename: Perfect Parity Refresh + Flipper Docs

## Highlights

- Total tools updated to 176 across both primary servers (refactored and modular)
- Flipper Zero toolkit fully documented (24 tools) with cross-platform guidance
- README and docs synced: badges, counts, and catalog reflect 176 tools
- Fixed Tools badge link to point to `docs/general/TOOL_CATALOG.md`
- Minor documentation cleanups and consistency improvements

## Details

- Parity maintained: Refactored and Modular servers both register the same 176 tools
- Count breakdown (practical): 120 exported registrations + runtime suites
  - Flipper Zero tool suite (24 tools) via `dev/src/tools/flipper`
  - MCP Web UI Bridge tools (6 tools) via `mcp-web-ui-bridge`
  - Additional advanced endpoints in server integrations
- Minimal profile unchanged: 15 core tools for lightweight environments

## Flipper Zero

- Full documentation available under `docs/tool/flipper/`
  - Device discovery/connection, FS ops, NFC/RFID, IR, Sub-GHz, BadUSB
  - UART/GPIO, BLE scan/pair, sessions, and safety controls
  - Cross-platform bridge workflow documented for Android/iOS
- Safety defaults: transmission features disabled unless explicitly enabled

## Documentation Updates

- README updated for 1.7b with 176 tool count, corrected badge link, and Flipper docs link
- Tool Catalog (`docs/general/TOOL_CATALOG.md`) updated with current counts and parity notes
- Tools overview (`docs/tools-README.md`) counts refreshed (120 exports, 176 endpoints)
- Category Index summary updated for 1.7b and date stamp

## Notes

- Prior 1.7 documents remain for historical reference; this 1.7b changelog supersedes counts
- No changes to runtime defaults or environment variables

— MCP God Mode 1.7b
