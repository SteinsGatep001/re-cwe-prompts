# CWE-<ID> <Title> — Report

Generated: <YYYY-MM-DD HH:MM TZ>
Target: <proto://host:port>
Tools: <IDA MCP | Ghidra>, probe scripts: <scripts/...>

## 1) Executive Summary
<One-paragraph summary of finding(s), impact, and confidence.>

## 2) Environment & Scope
- Binary/Version: <if known>
- Toolchain: <IDA/Ghidra versions + ida-pro-mcp version>
- Target metadata: `<target.json>` highlights (base_url, tls verify, rate_limit)
- Auth in scope: <none/basic/digest/bearer> (sanitized)
- Captures: `targets-local/<target-key>/captures/` used (time range, volume)

## 3) Captures & Data Processing
- Sources: <pcap/http logs/har>
- Processing methodology:
  - Extract request lines (method, path, query) → dedupe → seed `routes[]`
  - Parameter discovery (query/form/JSON/multipart) from captures
  - Header conventions observed: <Host/SNI, X-Original-URL, etc.>
- Artifacts: `evidence/top_request_lines.txt`, updated `target.json` (sanitized excerpt below)

## 4) Mutation/Probe Strategy (HTTP)
- Injection surfaces exercised: <path, query, headers, form, JSON, multipart filename>
- Payload families: <per CWE; encodings; mixed separators; unicode variants>
- Methods: <GET/POST>; Content-Types: <application/json | form | multipart>
- Controls: timeouts/rate limit/backoff; max attempts; proxies
- Script(s): <scripts/...> with key flags (`--max`, `--target-json`)

## 5) Dynamic Results Summary
- Attempts: <N total> across <S surfaces> and <F payload families>
- Indicators observed: <list of first/strongest indicators>
- Status: <Vulnerable | Not Reproducible | Inconclusive> (explain briefly)
- Evidence index: see Appendix A

## 6) Static Analysis (Role-Based Chains)
- Chains (2–3 hops):
  - <Route> → <Handler fn@addr> → <Utility fn@addr> → <Sink fn@addr>
- Controls observed (order): <decode | validate | canonicalize | prefix | sink>
- Gaps: <what is missing/misordered>

## 7) Key Functions (Summaries)
| Role | Function (name@addr) | Purpose | Inputs | Outputs/Effects | Guard Status |
|------|-----------------------|---------|--------|------------------|--------------|
| Router | <Router_*@0x...> | <brief> | <req path> | <dispatch> | <n/a> |
| Handler | <Handler_*@0x...> | <brief> | <path/query> | <build fs path> | <decode=?, validate=?, realpath=?, prefix=?> |
| Utility | <Sanitize_*@0x...> | <brief> | <str> | <normalized> | <what it checks> |
| Sink | <FS_Sink_*@0x...> | <brief> | <path> | <open/read/send> | <preconditions?> |

## 8) Root Cause
<Where/why the control chain breaks; specific functions/lines; misuse/misorder of controls; special cases (double-encoding, mixed separators, unicode)>

## 9) Fix Guidance
- Apply guard sequence at/near handler before any FS call:
  1) Decode/normalize percent-encodings/UTF‑8
  2) Validate segments (ban `..`, control chars, mixed separators)
  3) Canonicalize to absolute (realpath)
  4) Enforce base-directory prefix containment
- Patch points: <functions/lines>
- Unit tests: negative traversal vectors + positive legal paths

## 10) Verification Plan
- Static: confirm guard placement/order
- Dynamic: rerun probes with selected payloads; expect block/confinement

## Appendix A — Evidence Index (sanitized)
- Attempts JSONL: <path>
- Notable responses: <paths to truncated bodies>

## Appendix B — Reproduction Steps
1) Set up environment (RE_CWE_PROMPTS_DIR, target.json)
2) Run script(s) with flags: <command lines>
3) Open artifacts at: <paths>

## Appendix C — Target Metadata (sanitized excerpt)
```json
<target.json excerpt>
```
