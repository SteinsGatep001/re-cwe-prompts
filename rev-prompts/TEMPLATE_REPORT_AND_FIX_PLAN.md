# Report and Fix Plan Template

Report sections
1) Summary — vuln type, impact, exploitability
2) Environment — target, tools, probe scripts
3) Dynamic evidence — payloads, responses, indicators
4) Static analysis — route→handler→sink chain; controls present/absent
5) Root cause — missing/late controls
6) Fix guidance — guard sequence and placement
7) Verification — steps to re-test

Fix guidance (bind to code)
- Place guard sequence in the handler path before the first FS sink:
  1) Decode percent-encodings/UTF-8
  2) Validate segments: disallow "..", absolute paths, mixed separators, nulls
  3) Canonicalize with realpath; handle symlinks
  4) Enforce base-directory prefix
- Add tests for negative/positive cases; log and deny on failure.

File outputs
- Use `workflows/generate_report.md` and `workflows/write_reports.md` for naming and locations.

