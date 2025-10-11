# Roles (Dispatcher, Handler, Sanitizer, Sink)

Purpose
- Provide role-centric heuristics to classify functions during static analysis and to drive renaming/commenting consistently.

Roles and heuristics
- Dispatcher/Router
  - Fan-in from many xrefs; switches on strings like routes, verbs, or file names
  - Calls per-route handlers or table-driven jump logic
  - Rename prefix: `Router_` or `Dispatch_`
- Handler
  - Consumes request params (path, query, form parts) and orchestrates business logic
  - Often builds paths, selects actions, or performs authorization
  - Rename prefix: `Handler_`
- Sanitizer/Normalizer
  - Transforms or validates untrusted input (decode, strip, allowlist)
  - Rename prefix: `Sanitize_`, `Normalize_`
- Utility/Builder
  - String/URL/path building helpers; may be safe or unsafe depending on usage
  - Rename prefix: `Util_`, `Build_`
- Sink (Security-Relevant)
  - Performs sensitive operations: file open/stat/delete, command exec, process spawn, network redirect, SQL, template render
  - Rename prefix: `FS_`, `Exec_`, `Net_`, `DB_`, `Tpl_`

Commenting guidance
- At each role boundary, add a 1-line comment noting upstream/downstream and expected controls (e.g., “expects decoded+validated path; must call realpath before open”).

IDA/Ghidra notes
- Use call graph to spot role transitions; sinks are leaf- or near-leaf nodes with library calls.

