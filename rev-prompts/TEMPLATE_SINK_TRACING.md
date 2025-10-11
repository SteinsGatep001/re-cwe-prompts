# Sink Tracing Template (Bottom-Up)

Goal
- Start from risky sinks and walk to handlers, verifying guard placement.

Common sinks
- Filesystem: open, fopen, ifstream, readFile, stat, lstat, unlink, chdir, realpath
- OS command: system, popen, execve, CreateProcess
- Network: connect, sendto (for SSRF-like pivots)

Checklist
1) Enumerate imports for sinks; list their xrefs.
2) For each xref, decompile caller and identify role.
3) Walk up 2–3 hops to reach a handler or router.
4) At each hop, annotate transforms/guards.
5) Conclude guard sequence before the sink or flag gaps.

IDA MCP prompts
- Locate sinks by name/imports; `get_xrefs_to <sink_addr>`
- `decompile_function` callers; `get_callees` to expand chains
- `set_comment`: `role:sink|sanitize; controls:<...>`

Ghidra prompts
- Imports window; References to imported symbol
- Decompiler + Function Graph to navigate up-callers

Deliverable
- Handler → ... → Sink chain with control annotations and gap summary.

