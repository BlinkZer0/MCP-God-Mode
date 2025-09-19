---
trigger: always_on
---

---

## trigger: always_on

Rule: Tool Manifest as Source of Truth
Always load tools.manifest.json first and use it to choose tools. If the task is ambiguous, list candidate tools with brief rationale and wait for confirmation.

Rule: Self Healing & Smoke Tests
For any tool invocation, first run its smoke test from the manifest. If it fails, fix it without sacrificing intended functionality.

Rule: Naming & Duplicates
Do not invent or rename tools. If names collide, propose disambiguation in the manifest and request sign-off.

Rule: Minimal Surface Changes
Prefer additive edits, avoid breaking exports, and never remove a tool without a deprecation note and my approval.

Rule: Adding Tools
When adding tools they must be cross platform or offer an alternative with the same functionality. The platforms we support are Android, IOS, Windows, Linux, and MacOs. Every tool added needs to have a built in Natural Language Interface, and be properly documented within our readme (for tool count), and in the documentation wiki; there need be the tools own article, as well as updating the list of total tools. When adding a tool, thoroughly smoke test it.
