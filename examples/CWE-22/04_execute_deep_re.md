Prompt 04 — Execute Deep Reverse Engineering (CWE-22)

Goal
- Build handler→sink chains and audit traversal guards.

Tasks
1) Use `$RE_CWE_PROMPTS_DIR/workflows/discover_routes.md` and `trace_to_fs_sinks.md`.
2) Apply `rev-prompts/TEMPLATE_DISPATCHER_DISCOVERY.md`, `TEMPLATE_SINK_TRACING.md`, `TEMPLATE_FS_GUARD_AUDIT.md`, `TEMPLATE_RENAMING_AND_COMMENTS.md`.
3) Document control placement: decode → validate segments → canonicalize → prefix-check → sink.

