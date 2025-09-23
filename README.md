[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/blinkzer0-mcp-god-mode-badge.png)](https://mseep.ai/app/blinkzer0-mcp-god-mode)

<picture>
  <img src="assets/hero-animated.svg" alt="MCP God Mode banner" width="100%" />
</picture>

<p align="center">
  <a href="docs/wiki/Overview.md">Wiki Overview</a> ·
  <a href="#flagship-server">Flagship Server</a> ·
  <a href="docs/wiki/Tool-Router.md">Tool Router (Experimental)</a> ·
  <a href="docs/wiki/Catalog-Format.md">Catalog Format</a> ·
  <a href="docs/wiki/Usage-Examples.md">Usage & Examples</a> ·
  <a href="docs/wiki/Architecture.md">Architecture</a> ·
  <a href="docs/wiki/Troubleshooting.md">Troubleshooting</a>
</p>

One MCP to route them all. Find a tool you like? Route cause located.

Built on the Model Context Protocol (MCP). Cross-platform. Pluggable. Delightfully documented.

[![Version](https://img.shields.io/badge/Version-v2.1b-blue)](docs/updates/VERSION_2.1b_CHANGELOG.md)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D%2018-brightgreen)](package.json)
[![Platforms](https://img.shields.io/badge/Platforms-Win%20%7C%20macOS%20%7C%20Linux%20%7C%20Android%20%7C%20iOS-orange)](docs/general/CROSS_PLATFORM_COMPATIBILITY.md)
[![Tools](https://img.shields.io/badge/Tools-Catalog-orange)](TOOL_REFERENCE.md)

## Tool Count Proof

[![Proof of 190+ Tools in MCP God Mode](https://img.youtube.com/vi/CX9_DEss6Hk/0.jpg)](https://www.youtube.com/watch?v=CX9_DEss6Hk)

## What is MCP God Mode?

- A modular MCP server suite with a dynamic tool router, security tooling, and multi-platform support.
- Bring-your-own-tools: declare them in a JSON catalog and call them by name.
- Batteries included: discovery, description, and invocation endpoints via MCP tools.

## Quick Start

- Install Node 18+ and clone the repo
- Build TypeScript and start the flagship server

  - One-shot:

    - `npm run dev` (builds then runs `dist/server-refactored.js`)

  - Or just run:

    - `npm start` (runs `dist/server-refactored.js`)

- Optional (experimental): start the tool-router test server

  - `npm run tool-router:dev` (runs `servers/tool-router.js`)

- Call tools via MCP using the flagship server’s interface or, for router demos, the exposed `tool.list_catalog`, `tool.describe`, and `tool.call`

See: `docs/wiki/Usage-Examples.md`

## Documentation (Wiki Style)

- Start here: `docs/wiki/Overview.md`
- Flagship server details: see below
- Tool router details (experimental): `docs/wiki/Tool-Router.md`
- Catalog schema and examples: `docs/wiki/Catalog-Format.md`

## Precision Notes

- Flagship entry: `dist/server-refactored.js` (built from `dev/src/server-refactored.ts`)
- Router code (experimental): `servers/tool-router.js`
- Catalog path: `servers/router-registry/tools.json`
- Handlers: `servers/router-registry/handlers/*.js`

P.S. Our docs contain trace amounts of puns. Proceed with route caution.

## Flagship Server

The flagship, production-ready server is `server-refactored`:

- Build: `tsc -p .`
- Run: `npm start` (runs `dist/server-refactored.js`)
- Used by wrappers and tests across the repo

Note on tool-router: The tool-router (`servers/tool-router.js`) is an experimental test build used for exploring a catalog-driven routing surface. It is not the primary server and may change rapidly.

## Acknowledgments

We would like to express our sincere gratitude to the creators and maintainers of **TruffleHog** for their exceptional work in developing this powerful secret scanning tool.

### TruffleHog

Special thanks to the Truffle Security team for creating and maintaining [TruffleHog](https://github.com/trufflesecurity/trufflehog) - a comprehensive secret scanning tool that forms the backbone of our security scanning capabilities.

**TruffleHog Features Integrated:**
- 800+ secret detector types
- Cross-platform binary support
- Live credential verification
- Deep analysis capabilities
- Multi-source scanning (Git, Docker, S3, etc.)

The integration of TruffleHog into MCP God Mode enables professional-grade secret detection and analysis, making it accessible through our natural language interface. This integration would not be possible without the excellent foundation provided by the Truffle Security team.

**TruffleHog Repository:** [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)

We encourage users to star, contribute to, and support the TruffleHog project. Their continued development benefits the entire security community.
