# Pattern: CWE-XXX <Title> (Generic)

Captures-first
- Treat `targets-local/<TARGET_KEY>/captures/` request lines as primary evidence; seed `routes[]` in target.json and align static RE from observed paths (see `rev-prompts/TEMPLATE_REQUEST_LINE_DRIVEN.md`).

What to look for
- Sources: attacker‑controlled data entry points (URL path/query, headers, body fields)
- Transformations: decode/normalize/join/sanitize steps that change semantics
- Sinks: APIs where the weakness manifests (FS open, redirect header, shell spawn, template rendering)

Red flags
- Common anti‑patterns relevant to this CWE
- Tell‑tale source→sink chains missing controls (or misordered)

High‑level procedure (IDA Pro MCP)
1) Seed from captures; identify dispatchers/controllers via strings/xrefs.
2) Walk callees from dispatcher to potential sinks (2–3 hops), confirm with imports.
3) On each path, check control placement and order; record gaps; add comments and role‑driven renames.

Desired fix shape (control strategy)
- Controls to apply, and their correct order (e.g., decode→validate→canonicalize→enforce)
- Where to insert in the handler layer; what to avoid downstream.
Reference pseudo-code
```
// Tailor to CWE
```

Suggested dynamic spot‑checks
- A small list of payloads/conditions that safely demonstrate impact (or lack thereof)

MCP anchors (see `tool-notes/IDA_MCP.md`)
- Use `rename_function` with role patterns, `set_comment` with purpose/guard status, `set_function_prototype` and variable type setters. Apply the Callee Documentation Pass for coverage.

Reporting guidance
- Summarize dynamic evidence, role‑based call graph, root cause, fix, verification checklist.
