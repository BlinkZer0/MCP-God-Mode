# Archive Directory

This directory contains archived files that are no longer needed in the main project but are preserved for reference or potential future use.

## Structure

### `/backups/`
Contains backup files of the main server implementation:
- `server-refactored.ts.backup` - Backup versions of the main server file
- `server-refactored.ts.backup2` - Additional backup versions
- `server-refactored.ts.backup3` - Additional backup versions  
- `server-refactored.ts.backup4` - Additional backup versions

### `/experimental/`
Contains experimental and troubleshooting files:
- `server-refactored-fixed.ts` - Fixed version with implemented helper functions (troubleshooting)
- `server-bundled.js` - Bundled server version (experimental)
- `server-refactored-complete.js` - Complete server version (experimental)
- `server-ultra-minimal.ts` - Ultra minimal server version (experimental)

## Current Production Files

The main project now uses these clean, production-ready files:

### Source Files (`/src/`)
- `server-refactored.ts` - Main production server (modular architecture)
- `server-modular.ts` - Alternative modular approach
- `server-minimal.ts` - Lightweight minimal version

### Compiled Files (`/dist/`)
- `server-refactored.js` - Main production server (used by `npm start`)
- `server-modular.js` - Alternative modular approach
- `server-minimal.js` - Lightweight minimal version

## Notes

- All archived files are preserved for reference and potential future use
- The main production server is `server-refactored.js` which includes all 100+ tools
- Experimental files may contain incomplete implementations or troubleshooting code
- Backup files are from development iterations and are no longer needed

## Cleanup Date

Archived on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
