#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat << 'EOF'
Export example prompt pack into a downstream project (docs/prompts style)

Usage:
  scripts/export_prompts.sh --cwe CWE-22 \
    --target-url http://target:8010 \
    [--target-key http-target-8010] \
    [--out-dir ../docs/prompts] [--force]

Notes:
  - Picks templates from examples/<CWE>/ and renders placeholders:
      <TARGET_URL>, <TARGET_HOST>, <TARGET_PORT>, <TARGET_KEY>
  - Output directory structure: <out-dir>/<CWE>/<TARGET_KEY>/
  - Does not overwrite existing files unless --force is given.
EOF
}

out_dir="../docs/prompts"
cwe="CWE-22"
target_url=""
target_key=""
force_overwrite=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --out-dir) out_dir="$2"; shift 2 ;;
    --cwe) cwe="$2"; shift 2 ;;
    --target-url) target_url="$2"; shift 2 ;;
    --target-key) target_key="$2"; shift 2 ;;
    --force) force_overwrite=1; shift ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$target_url" ]]; then
  echo "--target-url is required" >&2
  usage; exit 1
fi

scheme=""; host=""; port=""
read -r scheme host port < <(python3 - <<PY
from urllib.parse import urlparse
u = input().strip() or ""
p = urlparse(u)
scheme = p.scheme or "http"
host = p.hostname or ""
port = p.port or (80 if scheme == "http" else 443 if scheme == "https" else "")
print(scheme, host, port)
PY
<<< "$target_url")

if [[ -z "$host" || -z "$port" ]]; then
  echo "Failed to parse host/port from --target-url: $target_url" >&2
  exit 1
fi

if [[ -z "$target_key" ]]; then
  target_key="${scheme}-${host}-${port}"
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
template_dir="$repo_root/examples/$cwe"
if [[ ! -d "$template_dir" ]]; then
  # Attempt to normalize CWE name like 22 -> CWE-22
  if [[ "$cwe" =~ ^[0-9]+$ ]]; then
    cwe="CWE-$cwe"
    template_dir="$repo_root/examples/$cwe"
  fi
fi

if [[ ! -d "$template_dir" ]]; then
  echo "Template pack not found: $template_dir" >&2
  exit 1
fi

dest_dir="$out_dir/$cwe/$target_key"
mkdir -p "$dest_dir"

echo "Exporting prompts from $template_dir -> $dest_dir"

for src in "$template_dir"/*.md; do
  fname="$(basename "$src")"
  dest="$dest_dir/$fname"
  if [[ -f "$dest" && $force_overwrite -ne 1 ]]; then
    echo "Skip existing: $dest (use --force to overwrite)"
    continue
  fi
  python3 - "$target_url" "$host" "$port" "$target_key" "$src" "$dest" <<'PY'
import sys
target_url, host, port, key, src, dest = sys.argv[1:7]
text = open(src,'r',encoding='utf-8').read()
text = (text
  .replace('<TARGET_URL>', target_url)
  .replace('<TARGET_HOST>', host)
  .replace('<TARGET_PORT>', str(port))
  .replace('<TARGET_KEY>', key)
)
open(dest,'w',encoding='utf-8').write(text)
print(f"Wrote {dest}")
PY
done

echo "Done. Review and adjust in: $dest_dir"

