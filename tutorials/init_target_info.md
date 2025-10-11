# Initialize Target Info (JSON, Private)

Goal
- Guide an AI agent to create a per‑target JSON descriptor for analysis and dynamic probes, stored in a gitignored local folder.

Where to store (private)
- Use `re-cwe-prompts/targets-local/<target-key>/target.json` (gitignored by `re-cwe-prompts/.gitignore`).
- Suggested `<target-key>` format: `<scheme>-<host>-<port>` (e.g., `http-example.local-8000`).
- Keep raw evidence under `re-cwe-prompts/targets-local/<target-key>/evidence/`.
- Keep unredacted reports under `re-cwe-prompts/reports-private/`.

Agent steps
1) Ensure private dirs exist:
   - Run `sh re-cwe-prompts/scripts/init_private_dirs.sh`.
2) Create the target folder: `re-cwe-prompts/targets-local/<target-key>/`.
3) Write `target.json` using the template below (fill fields from user context):
   - `base_url` must include protocol (http/https) and port if non‑default.
   - Set `tls.verify` and `tls.sni_host` when https is used.
   - Add `auth` only if needed (digest/basic/bearer/custom).
   - Keep a `redaction_map` for generating sanitized public reports.
4) Print the absolute path to the created `target.json`.

JSON template (fill and save as `target.json`)
```
{
  "name": "example.local",
  "base_url": "http://example.local:8000",
  "protocol": "http",
  "host": "example.local",
  "port": 8000,
  "tls": {
    "enabled": false,
    "verify": true,
    "sni_host": ""
  },
  "auth": {
    "type": "none",           // none|basic|digest|bearer|custom
    "username": "",
    "password": "",
    "realm": "",
    "nonce": "",
    "opaque": "",
    "token": ""
  },
  "headers": {
    "User-Agent": "re-cwe-agent/1.0",
    "Host": ""
  },
  "routes": [
    "/Storage.html",
    "/api",
    "/admin"
  ],
  "timeouts": { "connect": 5.0, "read": 10.0 },
  "proxy": { "http": "", "https": "" },
  "rate_limit": { "rps": 2, "burst": 4 },
  "notes": "Local test target",
  "redaction_map": {
    "example.local": "<target>",
    "user@example.local": "<user>"
  }
}
```

Minimal example
```
{
  "base_url": "http://example.local:8000",
  "protocol": "http",
  "host": "example.local",
  "port": 8000,
  "tls": { "enabled": false, "verify": true, "sni_host": "" },
  "auth": { "type": "none" }
}
```

Validation tips
- Ensure `base_url` and `host` match; `port` is an integer; booleans are lowercase JSON booleans.
- For HTTPS, set `tls.enabled=true`, configure `verify` per environment, and include `sni_host` if required.
- If using Digest auth, include `realm/nonce/opaque` when reproducing fixed‑nonce requests.

Using in workflows
- Dynamic probes can read `target.json` to set protocol, verify, headers, and rate limits.
- Reporting workflows should use `redaction_map` to sanitize public artifacts saved to `reports/`.

One‑shot agent prompt (copy/paste)
- "Create `re-cwe-prompts/targets-local/http-example.local-8000/target.json` using the JSON template in `re-cwe-prompts/tutorials/init_target_info.md: JSON template`. Set `base_url` to `http://example.local:8000`. Then print the absolute path to the file."

