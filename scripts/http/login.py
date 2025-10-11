#!/usr/bin/env python3
import argparse
from pathlib import Path
from typing import Optional

import requests

from .common import (
    load_target_config,
    build_session,
    build_url,
    evidence_dir_for_target_json,
    apply_rate_limit,
    save_cookies,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="HTTP login probe (basic/digest/bearer) using target.json")
    ap.add_argument("--target-json", required=True, help="Path to target.json (private)")
    ap.add_argument("--path", default="/", help="Path to probe (default /)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method to use")
    ap.add_argument("--out-cookies", default="cookies.json", help="Filename for saved cookies under evidence/")
    args = ap.parse_args()

    cfg = load_target_config(args.target_json)
    session, cfg = build_session(cfg)

    url = build_url(cfg, args.path)
    timeouts = cfg.get("timeouts", {}) or {}
    timeout = (float(timeouts.get("connect", 5.0)), float(timeouts.get("read", 10.0)))

    last_ts: Optional[float] = None
    last_ts = apply_rate_limit(cfg, last_ts)

    try:
        if args.method == "POST":
            resp = session.post(url, timeout=timeout)
        else:
            resp = session.get(url, timeout=timeout)
    except requests.RequestException as e:
        print(f"ERROR: request failed: {e}")
        return 2

    status = resp.status_code
    ok = 200 <= status < 400
    print(f"Login probe: {args.method} {url} -> {status}")

    # Save cookies to evidence
    ev_dir = evidence_dir_for_target_json(args.target_json)
    save_cookies(session, ev_dir / args.out_cookies)
    print(f"Saved cookies to {ev_dir / args.out_cookies}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

