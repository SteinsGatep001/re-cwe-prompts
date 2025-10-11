# Generate a Generic Traversal Report (Static + Dynamic)

Sections (recommended)
1) Executive summary — CWE and impact
2) Environment & scope — target, tools/versions, captures
3) Captures & data processing — how request lines/params were extracted and used
4) Mutation/probe strategy — surfaces, payload families, encodings, limits
5) Dynamic results — attempts, indicators, status, evidence index
6) Static analysis — role‑based call chains and guard order
7) Key functions — per‑function summaries and guard status
8) Root cause — where/why the chain fails
9) Fix guidance — guard sequence and patch points
10) Verification plan — static + dynamic re‑checks

Assembly steps
- Use decompiler + call graph to document roles and control placement
- Keep names role‑oriented; avoid tool‑ or symbol‑specific labels in the final report
 - For IDA MCP command references, see `tool-notes/IDA_MCP.md`.
 - Incorporate capture‑processing methodology and mutation strategy details to make results reproducible.

File output instructions
- Always include protocol in `<target>` (e.g., `http://example.local:8000` or `https://...`).
- Write the full report to `reports/` using this pattern: `reports/CWE-22_Report_<YYYYMMDD-HHMM>_<target>.md`
- Write a brief summary to `reports/` using this pattern: `reports/CWE-22_Summary_<YYYYMMDD-HHMM>_<target>.txt`
- If `reports/` does not exist, create it.

Refer to `templates/report_CWE_GENERIC.md` for a comprehensive Markdown report skeleton that includes captures, mutation strategy, dynamic results, key functions, and appendices.

Summary template (TXT)
```
CWE-22 summary — <target> — <YYYYMMDD-HHMM>
Status: <Vulnerable | Not Reproducible | Inconclusive>
Attempts: <N>  Surfaces: <S>  Families: <F>
Top route(s): <from captures>
Key chain(s): <route→handler→sink>
Missing controls: <decode | validate | canonicalize | prefix>
Suspect functions: <Handler_*@0x..., FS_Sink_*@0x...>
Next steps: <patch area + retest>
```

Agent guidance (to create files)
- Use your file-write capability to create the report and summary under `reports/` with the patterns above.
- Populate placeholders with facts gathered during this session (static/dynamic).
- Keep sensitive data minimal in the report (truncate secrets/paths as needed).
