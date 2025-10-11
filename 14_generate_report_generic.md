# Generate a Generic Traversal Report (Static + Dynamic)

Sections to include
1) Summary: one-paragraph description of vulnerability type (CWE-22) and impact.
2) Environment: target, toolchain (ida-pro-mcp), any scripts used for runtime probes.
3) Dynamic evidence: per-payload results (status, brief preview), highlighting any sensitive disclosure.
4) Static analysis: route→sink call graph (2–3 hops), with notes on the presence/absence of decoding, validation, canonicalization, and base-prefix checks.
5) Root cause: missing or misordered controls enabling traversal.
6) Fix guidance: decode→validate→canonicalize→prefix-check→FS, before any filesystem operations.
7) Verification checklist: static and dynamic steps to confirm the fix.

How to assemble (ida-pro-mcp)
- Collect call graph via `get_callees` recursively (limit 2–3 hops).
- Add `set_comment` to functions to annotate roles and security notes.
- Avoid specific function names in the write-up; refer to roles (dispatcher, static handler, path utility, FS sink wrapper).

