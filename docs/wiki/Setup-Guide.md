<p align="center">
  <img src="../../assets/headers/animated-header-3.svg" alt="MCP God Mode - Setup Guide" />
</p>

# Setup Guide

This guide shows how to set up a generic MCP server, and specifically MCP God Mode, with or without the interactive installer.

## Prerequisites

- Node.js 18 or newer
- Git (optional but recommended)

## Server Build Locations (Important)

- Sources: `dev/src/` (e.g., `dev/src/server-refactored.ts`)
- Build output: `dev/dist/` (e.g., `dev/dist/server-refactored.js`)
- Entry shim: `server.js` (loads `dev/dist/server-refactored.js`)

See more: [Project Structure](./Project-Structure.md)

---

## Option A: Use the Interactive Installer (Recommended)

The interactive installer lets you choose categories or individual tools, then creates a tailored build/config.

```bash
node dev/interactive-installer.js
```

After generation completes, run the server via the entry shim:

```bash
node server.js   # loads dev/dist/server-refactored.js
```

---

## Option B: Manual Build & Run

Build the flagship server artifacts and run them directly.

```bash
# Build a default (or custom) configuration
node dev/build-server.js       # or use npm scripts that dispatch into dev/

# Run via entry shim
node server.js                 # loads dev/dist/server-refactored.js

# Or run the compiled output directly (if present)
node dev/dist/server-refactored.js
```

Common npm scripts (entry points may call into `dev/` builders or compiled outputs):

- `npm run dev`   → build then run `server.js` → `dev/dist/server-refactored.js`
- `npm start`     → run `server.js` → `dev/dist/server-refactored.js`

---

## Catalog & Tools

- Tool catalog format and validation: [Catalog Format](./Catalog-Format.md)
- Full tool reference: `docs/TOOL_REFERENCE.md`
- For router experiments: `servers/router-registry/tools.json`

---

## Verifying MCP Integration

- This server implements MCP endpoints; you can connect compatible frontends (e.g., Claude Desktop, Cursor, LM Studio) by pointing them to the running server.
- See frontend integration notes in the repository’s guides if needed.

---

## Troubleshooting

- Ensure Node 18+.
- Confirm the build output exists: `dev/dist/server-refactored.js`.
- Use the entry shim: `node server.js`.
- Check logs for missing dependencies or platform prerequisites.

