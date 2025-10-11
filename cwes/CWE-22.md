# Pattern: CWE-22 Directory Traversal (Generic)

## What to look for
- Source: user-controlled URL path or filename coming from HTTP request parsing.
- Transformations: URL decoding, string ops, path joins, normalization.
- Sinks: filesystem APIs (open/stat/fopen/__xstat/readfile/mmap/SendFile-like) that use the path.
- Missing controls: per-segment validation (reject '.'/'..'/control chars), canonicalization (realpath), base-directory prefix enforcement.

## Red flags
- Direct concatenation of request path with a filesystem base path.
- URL-decoding performed but not followed by segment validation or canonical prefix check.
- Double-encoding bypasses (e.g., `%2e%2e/` chains) accepted as valid.

## High-level procedure (IDA Pro MCP)
1) Identify likely HTTP layer and route dispatchers via strings (e.g., protocol markers, generic route tokens) and function fan-out.
2) From dispatchers, walk callees toward sinks (FS functions). Stop when you hit open/stat/fopen-like imports or clearly filesystem-wrapping functions.
3) On each path, record presence/absence of sanitizers and canonicalization. Check order: decode → validate → canonicalize → enforce base, before any FS call.
4) Confirm whether any branch omits validation (particularly multi-segment paths).

## Desired fix shape
- Decode to a stable form, split into segments, validate each segment, realpath the candidate path, enforce prefix containment, only then call FS sinks.

## Advanced dynamic fuzz strategy
- Payload families (mix and match):
  - Segments: `../`, `..%2f`, `%2e%2e/`, `%252e%252e/`, `..\\`, `.%2e/`, `..;/`
  - Slashes: `/`, `%2f`, `%252f`, `\\`, `%5c`
  - Depth: repeat 1..8 segments; vary leading/trailing slashes
  - Unicode: U+002E variants, normalization edge cases
  - Absolute paths: `/etc/passwd`, `C:\\Windows\\win.ini` (for leakage indicators only)
- Combinators:
  - Join families: e.g., `..%2f..%2f`, `..\\..\\`, `..%252f..%252f`
  - Double-encoded chains: `%252e%252e%255c` sequences
  - Mixed separators: `/` with `\\`
- Detection heuristics:
  - Markers: `root:x:` snippet, `\r\n[General]`, XML/INI keys, directory listings
  - Error echoes containing candidate path or normalized path
  - Length deltas and content-type changes
- Probe scope:
  - Apply payloads to base routes and capture-derived endpoints
  - Honor timeouts and rate limits from `target.json`
- See also: `probes/CWE-22/python_probe_prompt.md` and `probes/CWE-22/python_fuzzer_prompt_advanced.md`
