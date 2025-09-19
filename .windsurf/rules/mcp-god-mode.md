---
trigger: always_on
---

Rule: Tool Manifest as Source of Truth
Always load tools.manifest.json first and use it to choose tools. If the task is ambiguous, list candidate tools with brief rationale and wait for confirmation.

Rule: Plan → Diff → Apply
In Planning Mode, outline a numbered plan; after approval, show diffs for every multi-file change before applying. Summarize what changed and update the plan after each step.

Rule: Safety & Smoke Tests
For any tool invocation, first run its smoke test from the manifest. If it fails, propose a fix or skip and continue. Do not run tools marked requires_privilege:true without explicit approval.

Rule: Naming & Duplicates
Do not invent or rename tools. If names collide, propose disambiguation in the manifest and request sign-off.

Rule: Minimal Surface Changes
Prefer additive edits, avoid breaking exports, and never remove a tool without a deprecation note and my approval.