# Filesystem Guard Audit Template (CWE-22)

Objective
- Audit the request→handler→sink path for traversal prevention: decode → validate segments → canonicalize → prefix-check → sink.

Controls and checks
1) Decode: percent-encodings, UTF-8 normalization, double-encoding.
2) Validate segments: reject "..", absolute roots, mixed separators, null bytes.
3) Canonicalize: realpath-like resolution; handle symlinks.
4) Prefix-check: enforce base-directory confinement on canonical path.
5) Sink: open/read/write only after all above controls.

Procedure
1) From dispatcher/handler, follow path parameter to utilities and sinks.
2) Identify where decode/validate/canonicalize/prefix-check occur; note ordering.
3) If any step occurs after the sink or is missing, flag as a gap.
4) Record test vectors for dynamic verification.

Test vectors (examples)
- ../etc/passwd, ..%2fetc%2fpasswd, %252e%252e/…, ..\\, mixed / and \\
- Leading/trailing encoded slashes, UTF-8 dot variants, absolute paths.

Deliverable
- Guard sequence diagram, gaps list, and fix recommendations bound to specific functions/lines.

