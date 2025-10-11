# Fix Checklist — Filesystem Guard (CWE-22)

Control sequence (before any FS call)
1) Decode percent-encodings and normalize UTF‑8
2) Validate path segments (ban `..`, `.` when unintended; normalize separators)
3) Canonicalize (absolute + realpath)
4) Prefix-enforce against allowed base directory

Verification
- Negative/positive test cases for traversal and normal access
- Ensure checks run before `open/fopen/stat/access/opendir` paths

