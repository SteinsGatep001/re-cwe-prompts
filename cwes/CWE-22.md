# Pattern: CWE-22 Directory Traversal (Generic)

Captures-first
- Treat `targets-local/<TARGET_KEY>/captures/` request lines as primary evidence. Start static RE from concrete paths/queries (see `rev-prompts/TEMPLATE_REQUEST_LINE_DRIVEN.md`).

What to look for
- Sources: user-controlled URL path/filename parsed from HTTP requests (dispatcher/handler parameter extraction).
- Transforms: URL decode/normalize, string ops, join, replace, canonicalization.
- Sinks: FS APIs (open/fopen/stat/__xstat/access/realpath/sendfile/mmap/ifstream/CreateFile) or wrappers.
- Missing controls: per-segment validation, canonicalization (realpath), base directory prefix enforcement, and correct order.

Red flags
- Direct concatenation of request path with a filesystem base path.
- URL-decoding performed but not followed by segment validation or canonical prefix check.
- Double-encoding bypasses (e.g., `%2e%2e/` chains) accepted as valid.
 - Mixed separators (`/` and `\\`) allowed; absolute roots honored.
 - Canonicalization after the FS call or on a different variable than the one used at the sink.

High-level procedure (IDA Pro MCP)
1) Seed routes from captures; list strings for path heads (e.g., `/Storage.html`) and HTTP markers; xref to candidate dispatchers.
2) From handlers, expand 2–3 hops with `get_callees` to path builders and FS wrappers; confirm with imports.
3) For each chain, audit guard order: decode → validate segments → canonicalize(realpath) → prefix-check → sink. Place `set_comment` at handler entry and sink callsites recording status.
4) Rename functions by role (`Router_*`, `Handler_*`, `Sanitize_*`, `FS_Sink_*`) and set prototypes/types where evident.

Strings/imports checklist (quick grep)
- Strings: `"/", "..", "%2e", "%2f", "Storage", "download", "file", "path", "api", "admin"`
- Imports: `open, fopen, __xstat/stat, access, read/open wrappers, realpath, CreateFileA/W`

Edge cases to confirm
- Double/percent-decoding (`%252e%252e/`), mixed separators (`/` vs `\\`), Windows drive letters, UNC (`\\host\share`).
- Unicode dot/normalization (U+002E variants, NFC/NFD); platform-specific normalization.
- Symlink traversal and canonicalization scope (realpath on file vs dirname, TOCTOU windows).
- Prefix-check correctness: ensure prefix compare uses canonical absolute path, not raw strings.

Desired fix shape
- Decode to a stable form; split into segments; validate each segment; canonicalize to absolute (realpath without following outside mount/jail); enforce base-directory prefix; only then call FS sinks.

Reference pseudo-code
```
// base = canonicalized allowed root (absolute)
path = url_decode(request.path)
if (!validate_segments(path)) return 400
abs = realpath(join(base, path))
if (!abs.starts_with(base + sep)) return 403
return send_file(abs)
```

Advanced dynamic fuzz strategy
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

MCP action anchors (see `tool-notes/IDA_MCP.md`)
- Role rename: `rename_function` to `Router_*`, `Handler_*`, `Sanitize_*`, `FS_Sink_*`
- Comments: `set_comment` at handler/sink with guard checklist status
- Prototypes/types: `set_function_prototype`, `set_local_variable_type`, `set_stack_frame_variable_type`
- Callees pass: iterate `get_callees` to annotate and rename downstream utilities and sinks
