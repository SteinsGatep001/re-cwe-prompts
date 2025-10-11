# Write Reports to `reports/` (Agent Workflow)

Goal
- Guide the AI agent (Codex/Claude) to produce both a full Markdown report and a short text summary under the repository `reports/` directory.

When to use
- After completing discovery, sink tracing, and gap analysis for a CWE pattern (e.g., CWE‑22).

Output locations
- Public (sanitized):
  - Full report: `reports/CWE-<ID>_Report_<YYYYMMDD-HHMM>_<target>.md`
  - Brief summary: `reports/CWE-<ID>_Summary_<YYYYMMDD-HHMM>_<target>.txt`
- Private (unredacted, optional):
  - Full report: `reports-private/CWE-<ID>_Report_<YYYYMMDD-HHMM>_<target>.md`
  - Brief summary: `reports-private/CWE-<ID>_Summary_<YYYYMMDD-HHMM>_<target>.txt`
- `<target>` should include protocol, e.g., `http://example.local:8000` or `https://host:port`.

Standalone prompts repo (submodule) note
- If you are running inside `re-cwe-prompts/` directly, you may use:
  - Public: `re-cwe-prompts/reports/` (if you choose to keep reports colocated)
  - Private (ignored): `re-cwe-prompts/reports-private/`
  - Per-target sensitive data (ignored): `re-cwe-prompts/targets-local/`

Agent steps
1) Ensure `reports/` exists; create it if missing.
2) If writing private artifacts, ensure `reports-private/` exists; it is gitignored.
3) Collect finalized facts from the session: targets, evidence, role‑based call chains, controls present/absent, fix shape.
4) Fill the templates below with concrete findings.
5) Produce a sanitized public report/summary under `reports/` (redact real IPs/credentials/secrets; use placeholders).
6) Optionally produce a private report/summary under `reports-private/` with full details.
7) Print the created file paths.

Protocol/TLS guidance
- Prefer specifying the full URL with scheme in `<target>`.
- If HTTPS was used, record TLS verification setting (verify true/false), any custom CA, and SNI/`Host` header if applicable.

Sanitization guidance
- For public artifacts in `reports/`, replace real IPs/domains/users/paths with placeholders (e.g., `<target>`, `<user>`, `<path>`), keep only minimal evidence.
- Store raw responses, screenshots, or sensitive details under `targets-local/<target>/` or `reports-private/`.
  - When running inside the prompts repo itself, store sensitive details under `re-cwe-prompts/targets-local/<target>/` or `re-cwe-prompts/reports-private/`.

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
- "Create the directory `reports/` if missing. Then create two files using the templates above with filled values from this session: the full Markdown report and the short TXT summary. Use `<target>` as a full URL (e.g., `http://example.local:8000`) and the current timestamp. After writing, print the file paths."
