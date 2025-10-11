#!/usr/bin/env python3
import argparse
import json
import mimetypes
from pathlib import Path
from typing import Optional, Tuple

import requests

from .common import (
    load_target_config,
    build_session,
    build_url,
    evidence_dir_for_target_json,
    apply_rate_limit,
    parse_kv_pairs,
)


def parse_file_arg(file_arg: Optional[str]) -> Tuple[Optional[str], Optional[Tuple[str, bytes, str]]]:
    """
    Format: field=@/path/to/file;type=content/type
    Returns: (field_name, (filename, data, content_type)) or (None, None)
    """
    if not file_arg:
        return None, None
    if "=@" not in file_arg:
        raise ValueError("file arg must be like field=@/path;type=content/type")
    field, rest = file_arg.split("=@", 1)
    path = rest
    ctype = None
    if ";type=" in rest:
        path, ctype = rest.split(";type=", 1)
    p = Path(path)
    data = p.read_bytes()
    if not ctype:
        ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
    return field, (p.name, data, ctype)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generic HTTP request tool using target.json")
    ap.add_argument("--target-json", required=True, help="Path to target.json (private)")
    ap.add_argument("--method", required=True, choices=["GET", "POST", "PUT"], help="HTTP method")
    ap.add_argument("--path", required=True, help="Request path (e.g., /api)")
    ap.add_argument("--params", default="", help="Query params in key=value&key2=value2")
    ap.add_argument("--data", default="", help="Form data in key=value&key2=value2 (POST/PUT)")
    ap.add_argument("--json", dest="json_body", default="", help="Raw JSON string (POST/PUT)")
    ap.add_argument("--file", default="", help="Multipart file: field=@/path;type=content/type")
    ap.add_argument("--save-body", action="store_true", help="Save response body to evidence folder")
    ap.add_argument("--out-name", default="response.bin", help="Filename for saved body")
    args = ap.parse_args()

    cfg = load_target_config(args.target_json)
    session, cfg = build_session(cfg)
    url = build_url(cfg, args.path)
    timeouts = cfg.get("timeouts", {}) or {}
    timeout = (float(timeouts.get("connect", 5.0)), float(timeouts.get("read", 10.0)))

    params = parse_kv_pairs(args.params)
    data = parse_kv_pairs(args.data)

    json_body = None
    if args.json_body:
        json_body = json.loads(args.json_body)

    files = None
    if args.file:
        field, triplet = parse_file_arg(args.file)
        if field and triplet:
            files = {field: triplet}

    last_ts: Optional[float] = None
    last_ts = apply_rate_limit(cfg, last_ts)

    try:
        if args.method == "GET":
            resp = session.get(url, params=params, timeout=timeout)
        elif args.method == "POST":
            if files:
                resp = session.post(url, params=params, data=data or None, files=files, timeout=timeout)
            elif json_body is not None:
                resp = session.post(url, params=params, json=json_body, timeout=timeout)
            else:
                resp = session.post(url, params=params, data=data or None, timeout=timeout)
        else:  # PUT
            if files:
                resp = session.put(url, params=params, data=data or None, files=files, timeout=timeout)
            elif json_body is not None:
                resp = session.put(url, params=params, json=json_body, timeout=timeout)
            else:
                resp = session.put(url, params=params, data=data or None, timeout=timeout)
    except requests.RequestException as e:
        print(f"ERROR: request failed: {e}")
        return 2

    print(f"{args.method} {url} -> {resp.status_code}")
    print(f"Headers: {dict(resp.headers)}")
    preview = resp.text[:256] if resp.headers.get("Content-Type", "").startswith("text/") else resp.content[:128]
    try:
        # Ensure preview is printable
        if isinstance(preview, bytes):
            preview = preview.decode("utf-8", errors="replace")
    except Exception:
        pass
    print(f"Body preview: {preview!r}")

    if args.save_body:
        ev_dir = evidence_dir_for_target_json(args.target_json)
        out_path = ev_dir / args.out_name
        out_path.write_bytes(resp.content)
        print(f"Saved response body to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

