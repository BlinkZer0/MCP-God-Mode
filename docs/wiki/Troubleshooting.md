<p align="center">
  <img src="../../assets/headers/animated-header-5.svg" alt="Troubleshooting" />
</p>

# Troubleshooting

## Common Issues

- Unknown tool
  - Check `name` in the request and `tools.json` for typos.
  - Ensure the entry is present and unique.

- Version mismatch
  - Align your request’s `version` with the catalog’s `version`.
  - Or omit `version` to accept the current catalog version.

- Handler error
  - Inspect `hint` in the returned error for exception details.
  - Verify `handlerPath` is correct and exports `default` or `handler`.

- Overloaded
  - The router is guarding with `MAX_INFLIGHT`. Back off per `retry_after_ms`.
  - Consider raising `MAX_INFLIGHT` if handlers are lightweight.

- Invalid args / output
  - If you enabled AJV, the error will describe missing properties or type mismatches.
  - Keep schemas and handlers in agreement—no schema drift.

If problems persist, take a deep route and breathe. Then check the logs.

