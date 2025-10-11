# Write Reports to `reports/` (Agent Workflow)

Goal
- Guide the AI agent (Codex/Claude) to produce both a full Markdown report and a short text summary under the repository `reports/` directory.

When to use
- After completing discovery, sink tracing, and gap analysis for a CWE pattern (e.g., CWE‑22).

Output locations
- Full report: `reports/CWE-<ID>_Report_<YYYYMMDD-HHMM>_<target>.md`
- Brief summary: `reports/CWE-<ID>_Summary_<YYYYMMDD-HHMM>_<target>.txt`

Agent steps
1) Ensure `reports/` exists; create it if missing.
2) Collect finalized facts from the session: targets, evidence, role‑based call chains, controls present/absent, fix shape.
3) Fill the templates below with concrete findings.
4) Write both files under `reports/` using the naming pattern.
5) Print the two created file paths.

Templates

Full report (Markdown)
```
# CWE-<ID> <Title> — Report

Generated: <YYYY-MM-DD HH:MM TZ>
Target: <proto://host:port>
Tools: <IDA MCP | Ghidra>, probe scripts: <scripts/...>

## 1) Summary
<One-paragraph summary of vulnerability and impact>

## 2) Environment
- Binary/Version: <if known>
- Analysis tools: <versions>
- Probe scripts & flags: <if any>

## 3) Dynamic Evidence
- Payloads tried: <list>
- Responses/indicators: <status codes, keywords>
- POC disclosure (if any): <brief snippet>

## 4) Static Analysis (Role-Based)
- Route→Handler→Utility→Sink: <short chain(s)>
- Controls observed (order): <decode | validate | canonicalize | prefix | sink>
- Gaps: <what is missing/misordered>

## 5) Root Cause
<Where/why the control chain breaks>

## 6) Fix Guidance
- <Control sequence and patch points>

## 7) Verification Checklist
- Static re‑inspection: <list>
- Dynamic re‑probe: <list>
```

Summary (TXT)
```
CWE-<ID> summary — <target> — <YYYYMMDD-HHMM>
Status: <Vulnerable | Not Reproducible | Inconclusive>
Key chain(s): <route→handler→sink>
Missing controls: <decode | validate | canonicalize | prefix>
Next steps: <patch area + retest>
```

Example invocation text (for the agent)
- "Create the directory `reports/` if missing. Then create two files using the templates above with filled values from this session: the full Markdown report and the short TXT summary. Use `<target>` as `http://192.168.159.249:8010` and the current timestamp. After writing, print the file paths."

