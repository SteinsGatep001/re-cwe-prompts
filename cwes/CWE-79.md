# Pattern: CWE-79 Cross-Site Scripting (Generic)

## What to look for
- Sources: user input rendered into HTML (templates, string builders) without encoding.
- Sinks: HTML responses, DOM‑building paths, JSON embedded into HTML without escaping.

## Red flags
- Direct concatenation of input into HTML/JS contexts.
- No context‑sensitive encoding (HTML, attribute, JS string).

## High‑level procedure (IDA Pro MCP)
1) Search for strings like `<html`, `</script>`, common template markers.
2) Xref to response builders; find where user data flows into buffers.
3) Check for encoding calls between source and sink.

## Desired fix shape
- Apply context‑appropriate encoding/escaping at the last write before output.
- Prefer safe templating APIs that auto‑escape.

## Dynamic spot‑checks
- Inject `<svg onload=alert(1)>` or `"'><img src=x onerror=alert(1)>` into reflected inputs (only in safe test envs).

## Advanced fuzz strategy
- Contexts: HTML body, HTML attribute, JS string, URL, CSS — use context-appropriate payloads and encodings.
- Payload families:
  - HTML: `<img src=x onerror=1>`, `<svg onload=1>`, `<iframe srcdoc=...>`
  - Attr: `" onmouseover=1 x="`, `' autofocus onfocus=1 '`
  - JS: `";alert(1);//`, `</script><script>alert(1)</script>`
  - URL: `javascript:alert(1)` in href/src where applicable
  - Template/polyglots: `${{constructor.constructor('alert(1)')()}}` (server-side template injection overlap)
- Encodings & wrappers: HTML entities, URL-encoding, double-encoding, UTF-7 (legacy), mixed case
- Heuristics: reflection markers, DOM break-out, event attributes echoed; CSP/report-only hints
- Detection: reflected payload fragments, execution side-effects (only in instrumented/lab env)
- Use captures to extract parameter names and inject across contexts; rate-limit and sanitize outputs.
