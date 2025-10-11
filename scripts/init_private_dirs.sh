#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$ROOT_DIR/targets-local" "$ROOT_DIR/reports-private"

if [ ! -f "$ROOT_DIR/targets-local/README.txt" ]; then
  cat > "$ROOT_DIR/targets-local/README.txt" << 'EOF'
This directory is gitignored (see re-cwe-prompts/.gitignore).
Use one subfolder per target with sensitive (private) data, e.g.:
  targets-local/
    http-example.local-8000/
      notes.md
      evidence/
      reports/
      sanitization.json   # optional redaction map for public copies

Do NOT commit real IPs/domains/credentials to the repo.
EOF
fi

if [ ! -f "$ROOT_DIR/reports-private/README.txt" ]; then
  cat > "$ROOT_DIR/reports-private/README.txt" << 'EOF'
This directory is gitignored. Place full, unredacted reports here for local use.
Public, sanitized copies should go to the tracked `reports/` folder (or a parent repo's `reports/`).
EOF
fi

echo "Initialized re-cwe-prompts private directories: re-cwe-prompts/targets-local/ and re-cwe-prompts/reports-private/"
