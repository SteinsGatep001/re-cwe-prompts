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

