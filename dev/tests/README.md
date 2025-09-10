# MCP God Mode Tests

This directory contains all test files and test results for the MCP God Mode project.

## Test Files

### Smoke Tests
- `smoke.mjs` - Comprehensive smoke test framework
- `smoke-simple.mjs` - Basic smoke test for core tools
- `smoke-comprehensive.mjs` - Extended smoke test for more tools
- `smoke_test_all_tools.mjs` - Legacy smoke test

### Specific Tool Tests
- `test_drone_tools_*.py` - Python tests for drone tools
- `test_drone_tools_*.js` - JavaScript tests for drone tools
- `test_drone_tools_*.mjs` - ES module tests for drone tools
- `test_cellular_website.js` - Cellular triangulation website tests
- `test_ss7_*.cjs` - SS7 protocol tests

### Test Results
- `*test-results*.json` - Test result files with timestamps
- `SMOKE_TEST_SUMMARY.md` - Summary of smoke test results

## Running Tests

To run the smoke tests:

```bash
# Basic smoke test
node tests/smoke-simple.mjs

# Comprehensive smoke test
node tests/smoke-comprehensive.mjs

# Full smoke test framework
node tests/smoke.mjs
```

## Test Results

The test results show that all tools are working correctly with a 100% success rate after the recent fixes for:
- TypeScript compilation errors
- ES modules compatibility issues
- Flipper tools registration
- Tool registration flow
