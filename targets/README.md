# Targets (Local, Sensitive Data)

Purpose
- Keep per-target sensitive details (real IPs, credentials, raw responses) out of git.

Recommended layout (local only)
- Create a top-level folder at repo root: `targets-local/` (gitignored).
- Inside, create one subfolder per target, e.g.:
  - `targets-local/http-example.local-8000/`
    - `notes.md` — private notes
    - `evidence/` — raw responses, screenshots
    - `reports/` — full unredacted reports (can also use root `reports-private/`)

Git hygiene
- `targets-local/` is ignored via `.gitignore` and should never be committed.
- Public artifacts should be sanitized (no real IPs, secrets) and saved to the tracked `reports/` directory.

Agent guidance
- When instructed to write reports, also produce a sanitized public copy for `reports/` and, if needed, a full private copy in `reports-private/` or under the relevant `targets-local/<target>/reports/`.
