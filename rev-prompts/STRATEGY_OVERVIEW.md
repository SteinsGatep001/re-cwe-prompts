# Reverse Engineering — Multi-Strategy Playbook

Purpose
- Provide multiple complementary strategies to drive deep reverse engineering for web-facing binaries/services and reliably surface vulnerabilities (start with CWE-22 traversal), producing a defensible fix plan.

How to use
- Pick one primary strategy (A or B) and run C/D as parallel sweeps. Use E to confirm data flows. Blend with dynamic probes (F) to validate hypotheses.

Strategy A — Top-Down Route Mapping
1) Entry points: identify HTTP dispatchers/routers, thread pools, and accept loops.
2) Route discovery: map path patterns to handlers; list route → handler symbols.
3) Handler slicing: for each handler, slice to utilities and potential I/O sinks.
4) Control audit: document guard placement (decode → validate segments → canonicalize → prefix-check) before FS sinks.

Strategy B — Bottom-Up Sink-Led Hunt
1) Enumerate filesystem sinks: open/read/write/chdir/stat/realpath/fopen/ifstream.
2) For each sink, walk xrefs upward 2–3 hops to handlers.
3) Check inbound data transformations and missing/late guards.
4) Prioritize reachable sinks from HTTP request paths.

Strategy C — String-Led Heuristic Sweep
1) Search strings: "/", "..", "%2e", "Storage.html", "download", "file", "path", "api", "admin".
2) Cross-reference string users; cluster by modules using them.
3) Flag URL decode/normalize utilities used in handlers.

Strategy D — Import-Led Triage
1) List imports: libcurl/http libs, libc FS calls, path utils.
2) Pivot from high-risk imports (open, system, popen, realpath) to callers.

Strategy E — Data-Flow Slice (Pseudo-Taint)
1) Sources: request path, query, headers, body.
2) Transforms: decode, normalize, join, replace.
3) Sinks: FS, OS cmd, DB, deserialization.
4) Slice from source symbols through transforms to sinks; annotate guards vs gaps.

Strategy F — Dynamic-Assisted Static
1) Generate scoped probes (e.g., traversal) using `probes/` prompts.
2) Use responses to narrow suspect handlers; align with static call chains.

IDA MCP checkpoints (see `tool-notes/IDA_MCP.md`)
- `list_strings_filter \/(GET|POST|route|Storage|download|file|path|api|admin)\/i`
- `get_xrefs_to <addr>` for string and sink cross-refs
- `decompile_function <addr>` for slicing handlers
- `get_callees <addr>` to expand 2–3 hop chains
- `set_comment <addr> "role: handler|sanitize|sink; notes"`

Ghidra checkpoints
- Search: Strings and References panels for path-related strings
- Decompiler + Function Graph: slice handlers to sinks
- Plate Comments: capture role and guard placement

Reporting
- Keep role-based naming; avoid vendor/tool-specific noise.
- Use `workflows/generate_report.md` and `workflows/write_reports.md`.
