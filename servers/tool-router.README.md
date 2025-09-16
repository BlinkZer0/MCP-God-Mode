# Tool Router Server

## Overview
Dynamic tool routing system that exposes a stable interface while internally managing a hot-reloadable registry of tools.

## Features
- Stable façade with three core tools (`tool.list_catalog`, `tool.describe`, `tool.call`)
- Dynamic registry with hot-reload capability
- Schema validation hooks for all inputs/outputs
- Cross-platform support (Windows, macOS, Linux)

## Documentation
- Wiki article: ../docs/wiki/Tool-Router.md
- Catalog format: ../docs/wiki/Catalog-Format.md

## Installation
```bash
npm install
```

## Running
```bash
# Development mode
npm run tool-router:dev

# Production
node servers/tool-router.js
```

## Platform Notes
### Windows
- Fully supported
- Use PowerShell for best results

### macOS/Linux
- Fully supported
- File watching works reliably

### iOS (iSH/Alt shells)
- Requires manual reload after registry changes
- File watching may not work reliably

### Android (Termux)
- Install Node 18+ via `pkg install nodejs`
- Manual reload recommended
