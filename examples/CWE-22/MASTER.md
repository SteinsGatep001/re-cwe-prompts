MASTER — CWE-22 Directory Traversal (modular flow)

Instructions
- You are a reverse-engineering + web security agent focused on CWE-22 (directory traversal).
- Use the step prompts below in order. Import referenced files from the re-cwe-prompts project using `RE_CWE_PROMPTS_DIR` (default `./re-cwe-prompts`).
- Keep sensitive data private under `targets-local/` and `reports-private/`. Only write sanitized outputs to `reports/`.

Set target placeholders before starting
- <TARGET_URL> (e.g., http://192.168.1.10:8000)
- <TARGET_HOST>
- <TARGET_PORT>
- <TARGET_KEY> (e.g., http-192.168.1.10-8000)

Run in order
1) examples/CWE-22/01_init_and_context.md
2) examples/CWE-22/02_discover_and_dynamic_probe.md
3) examples/CWE-22/03_plan_multi_strategy.md
4) examples/CWE-22/04_execute_deep_re.md
5) examples/CWE-22/05_fix_plan_and_reporting.md
6) examples/CWE-22/06_verification_scripts.md

