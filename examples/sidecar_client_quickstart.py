#!/usr/bin/env python3
"""Quickstart: protect and open a long-lived artifact via the sidecar (< 15 lines core).

Prerequisites:
  python -m src.sidecar_server --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import base64
import json
import urllib.request

SIDECAR = "http://127.0.0.1:8787"
MASTER = "demo-master-secret-change-me"


def post(path: str, body: dict) -> dict:
    req = urllib.request.Request(
        SIDECAR + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def main() -> None:
    payload = b"hello from an autonomous agent"
    # 1) Protect
    out = post(
        "/v1/protect",
        {
            "input_b64": base64.b64encode(payload).decode(),
            "master_secret": MASTER,
            "public_label": "QUICKSTART",
        },
    )
    print("protected:", out["stok_path"])

    # 2) Open (legitimate)
    opened = post(
        "/v1/open",
        {
            "stok_b64": out["stok_b64"],
            "key_b64": out["key_b64"],
            "master_secret": MASTER,
        },
    )
    assert opened["recoverable"] is True
    pt = base64.b64decode(opened["plaintext_b64"])
    assert pt == payload
    print("round-trip OK, payload_len=", len(pt))

    # 3) Open with wrong master must fail
    bad = post(
        "/v1/open",
        {
            "stok_b64": out["stok_b64"],
            "key_b64": out["key_b64"],
            "master_secret": "wrong",
        },
    )
    assert bad["recoverable"] is False
    print("wrong master rejected OK")


if __name__ == "__main__":
    main()
