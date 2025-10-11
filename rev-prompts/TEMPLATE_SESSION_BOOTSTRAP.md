# Session Bootstrap (IDA MCP or Ghidra)

Objective
- Stand up a consistent RE session: naming, roles, checkpoints, and a living plan.

Ground rules
- Roles: dispatcher, handler, sanitizer, utility, sink.
- Keep a short plan; mark steps done; one step in progress.
- Prefer 2–3 hop slices; document guards before sinks.

Steps
1) Scan strings for routing/file terms; shortlist addresses.
2) For each candidate, open decompiler view and identify function role.
3) Add plate/comments: `role:<...>; notes:<...>`; rename symbols accordingly.
4) Build route→handler map; list potential sinks per handler.
5) Create a work queue: handlers to slice, sinks to walk up.

IDA MCP helpers
- `list_strings_filter` with path keywords
- `get_xrefs_to` for strings/sinks
- `decompile_function`, `get_callees`
- `set_comment` at key addresses

Ghidra helpers
- Strings window filter; References; Decompiler; Function Graph
- Plate Comments for roles and guard placement

Exit criteria
- Route map created; at least one handler→sink chain fully annotated.

