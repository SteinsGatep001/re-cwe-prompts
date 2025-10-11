import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth


def load_target_config(path: str) -> Dict[str, Any]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def evidence_dir_for_target_json(target_json_path: str) -> Path:
    target_dir = Path(target_json_path).parent
    ev = target_dir / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    return ev


def build_session(cfg: Dict[str, Any]) -> Tuple[requests.Session, Dict[str, Any]]:
    s = requests.Session()
    headers = cfg.get("headers", {}) or {}
    if headers:
        s.headers.update(headers)

    proxies = cfg.get("proxy", {}) or {}
    if proxies:
        s.proxies.update(proxies)

    auth_cfg = (cfg.get("auth") or {})
    auth_type = (auth_cfg.get("type") or "none").lower()
    if auth_type == "basic":
        s.auth = HTTPBasicAuth(auth_cfg.get("username", ""), auth_cfg.get("password", ""))
    elif auth_type == "digest":
        s.auth = HTTPDigestAuth(auth_cfg.get("username", ""), auth_cfg.get("password", ""))
    elif auth_type == "bearer":
        token = auth_cfg.get("token", "")
        if token:
            s.headers["Authorization"] = f"Bearer {token}"

    # TLS verify
    tls = cfg.get("tls", {}) or {}
    verify = bool(tls.get("verify", True))
    s.verify = verify

    return s, cfg


def build_url(cfg: Dict[str, Any], path: str) -> str:
    base = (cfg.get("base_url") or "").rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def apply_rate_limit(cfg: Dict[str, Any], last_ts: Optional[float]) -> float:
    rl = cfg.get("rate_limit", {}) or {}
    rps = float(rl.get("rps", 0) or 0)
    if rps > 0:
        min_interval = 1.0 / rps
        now = time.time()
        if last_ts is not None:
            elapsed = now - last_ts
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
        return time.time()
    return time.time()


def save_cookies(session: requests.Session, out_path: Path) -> None:
    cookies = [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path} for c in session.cookies]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(cookies, indent=2), encoding="utf-8")


def parse_kv_pairs(pairs: Optional[str]) -> Dict[str, str]:
    if not pairs:
        return {}
    result: Dict[str, str] = {}
    for item in pairs.split("&"):
        if not item:
            continue
        if "=" in item:
            k, v = item.split("=", 1)
        else:
            k, v = item, ""
        result[k] = v
    return result

