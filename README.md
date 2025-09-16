<picture>
  <img src="assets/hero-animated.svg" alt="MCP God Mode banner" width="100%" />
</picture>

<p align="center">
  <a href="docs/wiki/Overview.md">Wiki Overview</a> ·
  <a href="docs/wiki/Tool-Router.md">Tool Router</a> ·
  <a href="docs/wiki/Catalog-Format.md">Catalog Format</a> ·
  <a href="docs/wiki/Usage-Examples.md">Usage & Examples</a> ·
  <a href="docs/wiki/Architecture.md">Architecture</a> ·
  <a href="docs/wiki/Troubleshooting.md">Troubleshooting</a>
</p>

One MCP to route them all. Find a tool you like? Route cause located.

Built on the Model Context Protocol (MCP). Cross-platform. Pluggable. Delightfully documented.

[![Version](https://img.shields.io/badge/Version-v2.0c-blue)](docs/updates/VERSION_2.0c_CHANGELOG.md)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D%2018-brightgreen)](package.json)
[![Platforms](https://img.shields.io/badge/Platforms-Win%20%7C%20macOS%20%7C%20Linux%20%7C%20Android%20%7C%20iOS-orange)](docs/general/CROSS_PLATFORM_COMPATIBILITY.md)
[![Tools](https://img.shields.io/badge/Tools-Catalog-orange)](docs/TOOL_REFERENCE.md)

## What is MCP God Mode?

- A modular MCP server suite with a dynamic tool router, security tooling, and multi-platform support.
- Bring-your-own-tools: declare them in a JSON catalog and call them by name.
- Batteries included: discovery, description, and invocation endpoints via MCP tools.

## Quick Start

- Install Node 18+ and clone the repo
- Start a server (see `server.js` or `start-mcp.js`)
- Add tools in `servers/router-registry/tools.json`
- Call tools via the MCP protocol using `tool.list_catalog`, `tool.describe`, and `tool.call`

See: `docs/wiki/Usage-Examples.md`

## Documentation (Wiki Style)

- Start here: `docs/wiki/Overview.md`
- Tool router details: `docs/wiki/Tool-Router.md`
- Catalog schema and examples: `docs/wiki/Catalog-Format.md`

## Precision Notes

- Router code: `servers/tool-router.js`
- Catalog path: `servers/router-registry/tools.json`
- Handlers: `servers/router-registry/handlers/*.js`

P.S. Our docs contain trace amounts of puns. Proceed with route caution.

