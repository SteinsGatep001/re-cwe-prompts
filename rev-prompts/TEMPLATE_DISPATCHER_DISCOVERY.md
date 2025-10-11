# Dispatcher/Router Discovery Template

Goal
- Identify HTTP dispatcher/router and map routes to handlers.

Checklist
1) Strings sweep: search for HTTP verbs, common endpoints, file keywords.
2) Cross-refs: open xrefs to these strings; rank callsites with request context.
3) Dispatcher candidates: look for large switch/if-chains on paths.
4) Route table patterns: arrays of path strings with function pointers.
5) Build route→handler table with addresses and module names.

IDA MCP prompts
- `list_strings_filter \/(GET|POST|route|Storage|download|file|path|cgi|api|admin)\/i`
- For each hit: `get_xrefs_to <str_addr>`, then `decompile_function <fn_addr>`
- Mark with `set_comment`: `role:dispatcher|handler`

Ghidra prompts
- Use Strings filter; Show References to selected string
- Decompile calling function; inspect switch/tables for routing

Deliverable
- A concise route map: path → handler (addr, module), notes.

