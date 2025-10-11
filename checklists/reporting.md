# Reporting Checklist

- Fill Summary, Environment, Dynamic Evidence, Static Analysis, Root Cause, Fix, Verification
- Remove tool-specific jargon from final narrative
- Include minimal sensitive data; truncate where appropriate
- Save to `reports/` using naming patterns (see `workflows/write_reports.md`)
- Record protocol explicitly (http/https); if https, include TLS verify setting and any SNI/Host overrides
- Produce a sanitized public copy for `reports/` (no real IPs, secrets); place unredacted copies in `reports-private/` (gitignored) or `targets-local/<target>/`
