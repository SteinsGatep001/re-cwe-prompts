Prompt 05 — Fix Plan and Reporting

Goal
- Turn findings into a concrete fix plan and generate artifacts.

Tasks
1) Use `$RE_CWE_PROMPTS_DIR/workflows/gap_analysis_and_fix.md` and `rev-prompts/TEMPLATE_REPORT_AND_FIX_PLAN.md`.
2) Place guards: decode → validate segments → canonicalize → prefix-check → sink. Bind to functions/lines.
3) Specify unit tests: negative traversal vectors and positive legal paths.
4) Generate full report and summary per `$RE_CWE_PROMPTS_DIR/workflows/generate_report.md` and `write_reports.md`.

