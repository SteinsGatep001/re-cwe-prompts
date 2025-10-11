# Generate a Generic Traversal Report (Static + Dynamic)

Sections
1) Summary — CWE type and impact
2) Environment — target, tools (IDA/Ghidra), probe scripts
3) Dynamic evidence — per‑payload status/previews, sensitive disclosure if any
4) Static analysis — role‑based call graph (2–3 hops), controls present/absent and order
5) Root cause — missing/incorrect control chain
6) Fix guidance — decode→validate segments→canonicalize→prefix‑check→FS
7) Verification checklist — static re‑inspection + dynamic re‑probe

Assembly steps
- Use decompiler + call graph to document roles and control placement
- Keep names role‑oriented; avoid tool‑ or symbol‑specific labels in the final report

File output instructions
- Always include protocol in `<target>` (e.g., `http://example.local:8000` or `https://...`).
- Write the full report to `reports/` using this pattern: `reports/CWE-22_Report_<YYYYMMDD-HHMM>_<target>.md`
- Write a brief summary to `reports/` using this pattern: `reports/CWE-22_Summary_<YYYYMMDD-HHMM>_<target>.txt`
- If `reports/` does not exist, create it.

Report template (Markdown)
```
# CWE-22 Directory Traversal — Report

Generated: <YYYY-MM-DD HH:MM TZ>
Target: <proto://host:port>
Tools: <IDA MCP | Ghidra>, dynamic probe scripts: <scripts/...>
Protocol/TLS: <http|https>, TLS verify: <true|false>, SNI/Host: <value if used>

## 1) Summary
<One-paragraph summary of vuln and impact>

## 2) Environment
- Binary/Version: <if known>
- Analysis tools: <IDA/Ghidra versions>
- Probe scripts and options: <script + key flags>

## 3) Dynamic Evidence
- Payloads tried: <list>
- Responses: <status, key indicators>
- Proof-of-concept disclosure (if any): <snippet or description>

## 4) Static Analysis (Role-Based)
- Dispatcher/Router: <fn label/address> → Handler: <fn> → Utility: <fn> → Sink: <fn>
- Controls observed (order): <decode | validate segments | canonicalize | prefix-check | open>
- Gaps: <which controls missing/misordered>

## 5) Root Cause
<Explain where/why controls are missing or post-sink>

## 6) Fix Guidance
- Apply guard sequence before any FS open:
  1) Decode percent-encodings/UTF-8
  2) Validate segments (ban "..", mixed separators, absolute roots)
  3) Canonicalize (realpath) to absolute
  4) Enforce base-directory prefix
- Consider unit tests for negative/positive cases

## 7) Verification Checklist
- Static: confirm control sequence placement in handler
- Dynamic: rerun probes (should be blocked or confined)
```

Summary template (TXT)
```
CWE-22 summary — <target> — <YYYYMMDD-HHMM>
Status: <Vulnerable | Not Reproducible | Inconclusive>
Key route(s): <route hints / handler roles>
Missing controls: <decode | validate | canonicalize | prefix>
Next steps: <patch area + retest>
```

Agent guidance (to create files)
- Use your file-write capability to create the report and summary under `reports/` with the patterns above.
- Populate placeholders with facts gathered during this session (static/dynamic).
- Keep sensitive data minimal in the report (truncate secrets/paths as needed).
