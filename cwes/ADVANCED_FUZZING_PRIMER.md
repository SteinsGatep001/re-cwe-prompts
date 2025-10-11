# Advanced Fuzzing Primer (Across CWEs)

Purpose
- Upgrade from simple, fixed payload lists to adaptive, combinatorial, and context-aware fuzzing strategies that align with static RE findings.

Key ideas
- Seed dictionaries from target: strings, routes, parameter names, error messages, and captures.
- Payload families per CWE, combined with encodings, separators, and context wrappers.
- Combinators: depth (n segments), mix (slash/backslash), double/triple encoding, and Unicode variants.
- Stateful sequences: prime a session (cookies/auth), then send crafted requests.
- Feedback loop: use response features (codes, length deltas, markers) to prioritize next probes.

Heuristics & scoring
- Signals: status codes (2xx/3xx/4xx/5xx), content-type changes, response length delta, presence of filesystem markers, Location headers, HTML/script reflections.
- Score by evidence strength; short-circuit if strong indicators seen (write full evidence).

Controls & safety
- Respect timeouts and rate limits; cap requests per run.
- Avoid destructive verbs unless authorized; prefer GET/HEAD.
- Sanitize IPs/tokens in public outputs.

Design patterns
- Layered generators: base payloads → encoding transforms → combinators → final URLs.
- Pluggable detectors: regex sets for indicators per CWE.
- Configurable via `target.json` (routes, auth, headers, proxies, rate limits).

