# Request-Line–Driven Reverse Engineering Template

Purpose
- Start from a captured HTTP request line and rapidly map it to dispatcher → handler → sink chains in the target binary/service. Useful when you have packets/captures first and need to align static RE to observed behavior.

Typical inputs
- Request line: `<REQUEST_LINE>` (e.g., `GET /Storage.html?domainName=foo&LMD=bar HTTP/1.1`)
- Target key: `<TARGET_KEY>` (e.g., `http-192.168.1.1-80`)
- Captures directory: `targets-local/<TARGET_KEY>/captures/` (pcaps/http logs)
- Evidence output: `targets-local/<TARGET_KEY>/evidence/`
- Prompts repo: `RE_CWE_PROMPTS_DIR=${RE_CWE_PROMPTS_DIR:-./re-cwe-prompts}`

Safety
- Only analyze authorized targets. Do not embed credentials or secrets in public artifacts.

Workflow
1) Parse the request line
   - Extract: method, path, query, and salient segments (e.g., `Storage.html`, `api`, `admin`, file-like segments).
   - Canonicalize: decode `%2e`, `%2f`, `+`, and normalize path traversal sequences for searching.
   - Append to `targets-local/<TARGET_KEY>/evidence/static_notes.md` for traceability.
   - Treat captures as primary evidence: if missing, acquire a minimal capture covering top routes. Maintain a `top_request_lines.txt` in `evidence/` for quick reference.

2) Seed route hints (captures → target.json)
   - From `captures/`, enumerate unique paths and add/update `routes[]` in `targets-local/<TARGET_KEY>/target.json` (dedupe).
   - Note query keys present in the request line; they help pivot to parameter-parsing utilities.

3) String-led static pivots (dispatcher/handler discovery)
   - Search strings for: path head (`/Storage.html`), verbs (`GET`, `POST`), and adjacent UI/router tokens (`download`, `file`, `path`, `admin`).
   - For each string address, list xrefs and collect nearby functions. Label candidates as `dispatcher`, `router`, or `handler` in comments.
   - Use: IDA MCP `list_strings_filter` and `get_xrefs_to`; Ghidra Strings and References.

4) Map handler → utilities → sinks
   - From candidate handlers, decompile and walk callees 2–3 hops.
   - Identify transformations: decode, join, normalize, canonicalize; note guard placement.
   - Identify sinks: FS (open/read/write/realpath), OS exec, archive extractors. Record addresses and callsites.

5) Guard audit for CWE-22 (if applicable)
   - Expected sequence before FS sinks: decode → validate segments → canonicalize → prefix-check → sink.
   - Compare observed chains vs `workflows/gap_analysis_and_fix.md` and `checklists/fix_fs_guard.md`.

6) Dynamic-assisted confirmation (optional)
   - Generate a probe from `probes/CWE-22/python_probe_prompt.md` to test the specific path/query.
   - Limit scope and rate; save results under `evidence/` and reference in notes.

Deliverables (commit-safe)
- Function labels/comments encoding roles: dispatcher/handler/sanitizer/sink.
- Evidence notes: `targets-local/<TARGET_KEY>/evidence/static_notes.md` with request-line, hypotheses, and findings.
- If vulnerable: a short fix plan referencing exact functions/lines; otherwise, note the guard sequence present.

IDA MCP checkpoints
- `list_strings_filter /(GET|POST|Storage|download|file|path|api|admin)/i`
- `get_xrefs_to <string_addr>` and inspect callers
- `decompile_function <addr>` to slice handlers and locate parameter parsing
- `get_callees <addr>` for 2–3 hop expansion toward sinks
- `set_comment <addr> "role: handler|sanitize|sink; notes"`

Ghidra checkpoints
- Strings search for path head and verbs; References to collect xrefs
- Decompiler + Function Graph: map handler → sink path
- Plate comments: summarize guard placement and missing controls

Linkages to existing prompts
- Use with: `rev-prompts/TEMPLATE_DISPATCHER_DISCOVERY.md` and `TEMPLATE_SINK_TRACING.md` for systematic coverage.
- For reporting/fix: `rev-prompts/TEMPLATE_REPORT_AND_FIX_PLAN.md` and `workflows/generate_report.md`.
