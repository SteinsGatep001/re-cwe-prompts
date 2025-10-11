# Pattern: CWE-XXX <Title> (Generic)

## What to look for
- Sources: where attacker‑controlled data enters (e.g., URL path, headers, body fields)
- Transformations: decoding/normalization steps that may change semantics
- Sinks: APIs that make the vulnerability manifest (e.g., FS open, redirect header, shell spawn, template rendering)

## Red flags
- Common anti‑patterns relevant to this CWE
- Tell‑tale API pairs (source→sink) without controls

## High‑level procedure (IDA Pro MCP)
1) Identify dispatchers/controllers via strings and xrefs.
2) Walk callees from dispatcher to potential sinks (2–3 hops), confirm with imports.
3) On each path, check control placement and order; record gaps.

## Desired fix shape (control strategy)
- Controls to apply, and their correct order (e.g., decode→validate→canonicalize→enforce)
- Where to insert in the handler layer; what to avoid downstream.

## Suggested dynamic spot‑checks
- A small list of payloads/conditions that safely demonstrate impact (or lack thereof).

## Reporting guidance
- Summarize dynamic evidence, role‑based call graph, root cause, fix, verification checklist.

