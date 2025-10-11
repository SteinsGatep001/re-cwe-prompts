# CWE-22 Session Seed (IDA MCP, Generic)

Purpose
- Copy this entire block into your Codex/Claude session that is connected to IDA MCP to drive a generic CWE‑22 analysis without relying on specific symbol names.

Notes
- If the agent cannot read local files, ask me to paste contents of the referenced guides, or proceed based on the plan below.
- Keep outputs minimal but actionable; add short comments and role‑oriented renames only.
 - For IDA MCP command cheatsheet, see `re-cwe-prompts/tool-notes/IDA_MCP.md`.

Starter prompt (copy/paste into the other session)

"""
You are connected to an IDA MCP environment. Goal: Apply a generic CWE‑22 (Directory Traversal) analysis using re‑cwe‑prompts.

Scope files to load for context (do not print full contents, just skim structure and headings). If file access fails, continue with the plan:
- re-cwe-prompts/INDEX.md
- re-cwe-prompts/cwes/CWE-22.md
- re-cwe-prompts/workflows/discover_routes.md
- re-cwe-prompts/workflows/trace_to_fs_sinks.md
- re-cwe-prompts/workflows/gap_analysis_and_fix.md
- re-cwe-prompts/workflows/generate_report.md
- re-cwe-prompts/workflows/write_reports.md

Plan:
1) Verify IDA MCP connection and binary is loaded.
2) Discover request routes/dispatchers (generic, no specific names).
3) Trace routes to filesystem sinks.
4) Do CWE‑22 gap analysis (decode→validate segments→canonicalize→prefix‑check).
5) Add comments/rename functions to roles.
6) Summarize a mini report.
7) Persist report and summary files under `reports/`.

Actions:
- Step 1 (connection)
  - Call ida-pro-mcp__check_connection. If disconnected, pause and ask me to open the IDA DB and start the plugin.

- Step 2 (discover routes) — follow discover_routes.md
  - List strings with HTTP markers: call ida-pro-mcp__list_strings_filter with patterns: "http", "GET ", "POST ", ".html", "cgi", ".do", "/api", "/admin", "domainName=", "Content-Type".
  - For each interesting string, call ida-pro-mcp__get_xrefs_to to find candidate dispatchers/handlers.
  - For each candidate function: ida-pro-mcp__decompile_function and ida-pro-mcp__get_callees.
  - Tag functions by role (dispatcher, router, handler, sanitizer, utility). Use ida-pro-mcp__set_comment to annotate roles; use ida-pro-mcp__rename_function only when names are generic (e.g., sub_1234 → Handler_StaticResource_Serve).

- Step 3 (trace to FS sinks) — follow trace_to_fs_sinks.md
  - In handler call graphs (2–3 hops), search for filesystem APIs in pseudocode/asm: open, fopen, stat, access, opendir, readFile, CreateFile, PathCombine, realpath.
  - Confirm whether path inputs derive from request fields (URL path, query, form filenames). If needed, follow back through string builders and decode helpers.
  - Record each route→handler→utility→sink chain with comments (one comment per function mentioning upstream/downstream).

- Step 4 (CWE‑22 gap analysis) — follow gap_analysis_and_fix.md and CWE-22.md
  - Check for the control sequence before any FS call:
    1) Decode/normalize percent-encodings and UTF‑8
    2) Validate path segments (ban "..", "." when not intended; handle mixed separators)
    3) Canonicalize: realpath/normalize to absolute
    4) Prefix‑enforce against an allowed base directory
  - If any step is missing or done after the FS call, mark as vulnerable and add ida-pro-mcp__set_comment at the handler and sink.

- Step 5 (rename/comment for clarity)
  - For generic names starting with sub_, rename to descriptive role names (e.g., Router_Admin_Dispatch, Handler_StaticResource_Storage, FS_Sink_OpenRaw) using ida-pro-mcp__rename_function.
  - Add short comments ("Requires decode→segment validation→realpath→prefix before file open") using ida-pro-mcp__set_comment.

- Step 6 (mini report)
  - Produce a concise summary: affected routes, vulnerable chains, missing controls, recommended fix shape (guard function pseudocode).
  - Base structure on generate_report.md.

- Step 7 (persist files) — follow write_reports.md
  - Create directory `reports/` if missing.
  - Write full Markdown report to: `reports/CWE-22_Report_<YYYYMMDD-HHMM>_<target>.md`.
  - Write short TXT summary to: `reports/CWE-22_Summary_<YYYYMMDD-HHMM>_<target>.txt`.
  - Replace `<target>` with the analyzed URL including protocol (e.g., `http://example.local:8000`). If HTTPS is used, note TLS verify (true/false) and any SNI/Host header.

Proceed step-by-step, showing the IDA MCP calls and concise results at each phase. Stop if connection is not available.
"""
