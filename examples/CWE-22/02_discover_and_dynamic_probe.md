Prompt 02 — Discover + Dynamic Probe (use captures)

Goal
- Discover routes using captures, then generate and run a traversal probe.

Inputs
- Captures: `targets-local/<TARGET_KEY>/captures/`
- Target JSON: `targets-local/<TARGET_KEY>/target.json`

Tasks
1) Parse captures to extract endpoints; update `routes` in target.json (dedupe).
2) Quick sweep: GET `/`, `/robots.txt`, `/sitemap.xml`, `/Storage.html`, `/api`, `/admin` and capture-derived endpoints; log to evidence JSONL.
3) Generate traversal probe from `$RE_CWE_PROMPTS_DIR/probes/CWE-22/python_probe_prompt.md` into `scripts/probes/cwe22_probe.py`.
4) Run: `python3 scripts/probes/cwe22_probe.py --target-json targets-local/<TARGET_KEY>/target.json --max 100`
5) Save raw evidence under `targets-local/<TARGET_KEY>/evidence/` and a sanitized summary to `reports/` per `$RE_CWE_PROMPTS_DIR/workflows/write_reports.md`.

