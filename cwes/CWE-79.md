# Pattern: CWE-79 Cross-Site Scripting (Generic)

Captures-first
- Extract reflected parameters from `captures/` and prioritize routes where inputs echo in responses (status 200 with payload fragments).

What to look for
- Sources: attacker-controlled inputs (query, form, headers, path params) rendered into HTML/JS/CSS/URL contexts.
- Sinks: response builders (HTML templates, string builders), script blocks, attributes, inline event handlers, JSON embedded in HTML without escaping.

Red flags
- Direct concatenation of input into HTML/JS contexts.
- No context‑sensitive encoding (HTML, attribute, JS string).
 - JSON embedded in `<script>` without escaping, then parsed by the client.
 - Dangerous wrappers: `innerHTML`-equivalent server builders, string concatenations around `<script>`.

High‑level procedure (IDA Pro MCP)
1) From captures, list top routes/params. Search strings: `<html`, `<script`, `</script>`, `content-type: text/html`, template markers.
2) Xref to response builders; decompile; locate where inputs join output buffers; classify context (HTML body, attribute, JS string, URL, CSS).
3) Check for encoding/escaping before sink; verify context-appropriate routine used.
4) Rename handlers/utilities (`Handler_*_Render`, `Encode_HTML`, `Encode_JS`) and comment missing encoders.

Desired fix shape
- Apply context‑appropriate encoding/escaping at the last write before output; centralize encoders.
- Prefer safe templating APIs that auto‑escape; avoid string concatenation for markup/script.

Dynamic spot‑checks
- Inject payloads (safe lab only) into reflected inputs and confirm reflection/neutralization.
  - HTML body: `<svg onload=1>`
  - Attribute: `" onmouseover=1 x="`
  - JS string: `";alert(1);//` or `</script><script>1</script>`

Advanced fuzz strategy
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

MCP action anchors (see `tool-notes/IDA_MCP.md`)
- Identify response builders, tag with `set_comment` context and encoder presence.
- Rename encoder utilities (`Encode_HTML`, `Encode_Attr`, `Encode_JS`); ensure callers use them in correct context.
- If templates exist, label template render entrypoints; set prototypes for render functions to expose inputs.
