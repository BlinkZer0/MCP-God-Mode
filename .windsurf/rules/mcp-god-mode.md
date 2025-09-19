---
trigger: always_on
---

Rule: Smoke test and self healing.
For any tool invocation, first run its smoke test from the manifest. If it fails, fix it using the documentation as a functionality guide or, skip and continue.

Rule: Naming & Duplicates
Do not invent or rename tools. If names collide, propose disambiguation in the manifest and request sign-off.

Rule: Minimal Surface Changes
Prefer additive edits, avoid breaking exports, and never remove a tool without a deprecation note and my approval.

Rule: Adding tools
When adding tools update the manifest with them, as well as the index, and necessary documentation in the same formatting as the other tools.

Rule: Adding tools (cont.)
When adding an MCP tool it needs to have Mac, Windows, Linux, IOS, and Android support, and needs to have a Natural Language Interface.

Rule: Server Parity
Our flagship server is server-refactored.js, but all builds must be maintained on a modification. Servers are located in dev/src.

Rule: Documentation Parity
Tool Counts must be updated in the readme and documentation when a tool is added to the servers.
