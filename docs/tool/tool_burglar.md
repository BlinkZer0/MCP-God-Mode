# tool_burglar

Cross-repo importer + local tool manager for MCP-God-Mode.

## Features
- **Discover/Import** tools from external MCP repos (Git URLs or local paths).
- **Preview**: license & conflict checks, rename/prefix plan, dry-run.
- **Manage Local Tools**: list, enable, disable, rename, move, export, deprecate.
- **Parity**: auto-patch registrations in both server modes.
- **Audit/Confirm**: respects `MCPGM_AUDIT_ENABLED` and `MCPGM_REQUIRE_CONFIRMATION`.

## Examples

**Discover from repo**
```json
{ "action": "discover", "sources": ["https://github.com/some/mcp-repo"] }
```

**Dry-run import with prefix**
```json
{ "action": "preview_import", "sources": ["https://github.com/some/mcp-repo"], "include": ["wifi_*","bluetooth_*"], "prefix": "ext_" }
```

**Import (will prompt if confirmation required)**
```json
{ "action": "import_tools", "sources": ["https://github.com/some/mcp-repo"], "include": ["wifi_scan"], "prefix": "ext_", "auto_deps": true }
```

**List vendored sources**
```json
{ "action": "list_sources" }
```

**List local tools**
```json
{ "action": "list_local" }
```

**Enable/Disable**
```json
{ "action": "enable", "tool": "ext_wifi_scan" }
{ "action": "disable", "tool": "ext_wifi_scan" }
```

**Rename / Move / Export**
```json
{ "action": "rename", "tool": "ext_wifi_scan", "new_name": "wifi_scan_ext" }
{ "action": "move", "tool": "wifi_scan_ext", "dest_dir": "external/promoted" }
{ "action": "export", "tool": "wifi_scan_ext", "export_path": "exports/" }
```

**Natural-language**
```json
{ "nl_command": "grab bluetooth and wifi tools from https://github.com/some/mcp using prefix ext_ but dry run first" }
```

## Notes

- Imported files land under `dev/src/tools/external/<sourceName>/....`
- A rollback plan is saved under `.mcp_rollback/`.
- Import audit logs (if enabled) under `.mcp_audit/tool_burglar.log`.
- License detection is heuristic; non-MIT/Apache will warn and may require `force:true`.

## How to Use (quick)

- Add these files.
- Build/start your server(s).
- Call via **natural language**:
  - "**steal** the bluetooth tools from `https://github.com/…` with prefix `ext_`, **dry run** first"
- Or structured calls (examples in the doc).

Also tailor the registration patcher to exact file names in your project.

## Actions

### External Repository Operations

- **`discover`**: Scan external repos for MCP tools without importing
- **`preview_import`**: Show import plan with license checks and conflicts
- **`import_tools`**: Import tools from external repos with registration
- **`update_tools`**: Update previously imported tools from upstream
- **`remove_tools`**: Remove imported tools and clean up registrations

### Local Tool Management

- **`list_sources`**: List previously imported external sources
- **`list_local`**: List all local tools in the project
- **`enable`**: Enable a disabled tool
- **`disable`**: Disable a tool (comment out registrations)
- **`rename`**: Rename a tool and update all references
- **`move`**: Move a tool to a different directory
- **`export`**: Export a tool to an external location
- **`deprecate`**: Mark a tool as deprecated (disable with deprecation notice)

## Parameters

### Cross-Repository Parameters
- `sources`: Array of Git URLs or local paths to scan
- `include`: Array of tool name patterns to include (supports glob patterns)
- `exclude`: Array of tool name patterns to exclude
- `prefix`: String prefix to apply to imported tool names
- `dry_run`: Boolean to preview changes without applying
- `force`: Boolean to override license/risk warnings
- `auto_deps`: Boolean to automatically handle dependencies

### Local Management Parameters
- `tool`: Tool name for local management operations
- `new_name`: New name for rename operations
- `dest_dir`: Destination directory for move operations
- `export_path`: Export destination path

### Natural Language
- `nl_command`: Natural language command that gets parsed into structured parameters

## Security & Compliance

The tool respects the following environment variables:
- `MCPGM_REQUIRE_CONFIRMATION`: Requires user confirmation for destructive operations
- `MCPGM_AUDIT_ENABLED`: Enables audit logging of all operations

## File Structure

```
dev/src/tools/external/
├── source-repo-1/
│   ├── tool1.ts
│   ├── tool2.ts
│   └── tool1.ts.LICENSE.txt
└── source-repo-2/
    └── tool3.ts

.mcp_rollback/
└── tool_burglar-{timestamp}.json

.mcp_audit/
└── tool_burglar.log

docs/external/
└── import-{hash}.md
```
