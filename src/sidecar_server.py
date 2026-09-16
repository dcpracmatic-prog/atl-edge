#!/usr/bin/env python3
"""
Minimal SmartTokenProd sidecar — HTTP over localhost / 0.0.0.0.

Exposes long-lived protect / open / friction / status without requiring the
caller to embed the library. Intended for local multi-process agents and as
a building block for a future Kubernetes sidecar.

This is deliberately NOT a distributed consensus layer. Friction remains
file-local (authenticated inside each .stok). Shared multi-worker state
still requires an external FrictionStore.

Endpoints
---------
GET  /health
GET  /v1/status
POST /v1/protect   JSON: {input_path|input_b64, master_secret, public_label?}
POST /v1/open      JSON: {stok_path|stok_b64, master_secret, key_path|key_b64?}
GET  /v1/friction?path=...

Bind with --host 127.0.0.1 (default) for local-only, or 0.0.0.0 in containers.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from src.http_limits import BodyLimitError, REQUEST_SOCKET_TIMEOUT, read_bounded_json

_PKG = Path(__file__).resolve().parents[1]
for p in (str(_PKG), str(_PKG / "vendor")):
    if p not in sys.path:
        sys.path.insert(0, p)

from src.long_lived_protection import (  # noqa: E402
    is_available,
    status as llp_status,
    protect_artifact,
    open_artifact,
    artifact_friction_status,
)

DATA_DIR = Path(os.environ.get("ATL_DATA_DIR", "/tmp/atl-sidecar"))


def _json_response(handler: BaseHTTPRequestHandler, code: int, body: Dict[str, Any]) -> None:
    data = json.dumps(body, default=str).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _read_json(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    return read_bounded_json(handler.rfile, handler.headers)


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


class Handler(BaseHTTPRequestHandler):
    server_version = "ATL-Sidecar/1.0"

    def setup(self) -> None:
        super().setup()
        try:
            self.connection.settimeout(REQUEST_SOCKET_TIMEOUT)
        except Exception:
            pass

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            _json_response(self, 200, {"ok": True, "available": is_available()})
            return
        if parsed.path == "/v1/status":
            _json_response(self, 200, llp_status())
            return
        if parsed.path == "/v1/friction":
            qs = parse_qs(parsed.query)
            path = (qs.get("path") or [None])[0]
            if not path:
                _json_response(self, 400, {"error": "path query required"})
                return
            try:
                _json_response(self, 200, artifact_friction_status(path))
            except Exception as e:
                _json_response(self, 400, {"error": str(e)})
            return
        _json_response(self, 404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = _read_json(self)
        except BodyLimitError as e:
            _json_response(
                self,
                413 if "too_large" in e.reason else 400,
                {"error": e.reason},
            )
            return
        except Exception as e:
            _json_response(self, 400, {"error": f"invalid json: {e}"})
            return

        if parsed.path == "/v1/protect":
            self._protect(body)
            return
        if parsed.path == "/v1/open":
            self._open(body)
            return
        _json_response(self, 404, {"error": "not found"})

    def _protect(self, body: Dict[str, Any]) -> None:
        if not is_available():
            _json_response(self, 503, {"error": "SmartTokenProd unavailable", "status": llp_status()})
            return
        master = body.get("master_secret")
        if not master:
            _json_response(self, 400, {"error": "master_secret required"})
            return
        if isinstance(master, str):
            master_b = master.encode("utf-8")
        else:
            master_b = _b64d(master)

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(DATA_DIR)) as tmp:
            tmp_path = Path(tmp)
            if body.get("input_path"):
                src = Path(body["input_path"])
                if not src.is_file():
                    _json_response(self, 400, {"error": f"input_path not found: {src}"})
                    return
            elif body.get("input_b64"):
                src = tmp_path / "input.bin"
                src.write_bytes(_b64d(body["input_b64"]))
            else:
                _json_response(self, 400, {"error": "input_path or input_b64 required"})
                return

            label = body.get("public_label", "ATL-SIDECAR")
            if isinstance(label, str):
                label_b = label.encode("utf-8")
            else:
                label_b = b"ATL-SIDECAR"

            try:
                stok, key = protect_artifact(
                    src,
                    master_secret=master_b,
                    public_label=label_b,
                )
                # Persist into DATA_DIR for subsequent opens by path
                out_dir = DATA_DIR / "artifacts"
                out_dir.mkdir(parents=True, exist_ok=True)
                final_stok = out_dir / stok.name
                final_key = out_dir / key.name
                final_stok.write_bytes(stok.read_bytes())
                final_key.write_bytes(key.read_bytes())
                _json_response(
                    self,
                    200,
                    {
                        "stok_path": str(final_stok),
                        "key_path": str(final_key),
                        "stok_b64": _b64e(final_stok.read_bytes()),
                        "key_b64": _b64e(final_key.read_bytes()),
                    },
                )
            except Exception as e:
                _json_response(
                    self,
                    500,
                    {"error": str(e), "traceback": traceback.format_exc()},
                )

    def _open(self, body: Dict[str, Any]) -> None:
        if not is_available():
            _json_response(self, 503, {"error": "SmartTokenProd unavailable", "status": llp_status()})
            return
        master = body.get("master_secret")
        if not master:
            _json_response(self, 400, {"error": "master_secret required"})
            return
        master_b = master.encode("utf-8") if isinstance(master, str) else _b64d(master)

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(DATA_DIR)) as tmp:
            tmp_path = Path(tmp)
            if body.get("stok_path"):
                stok_path = Path(body["stok_path"])
            elif body.get("stok_b64"):
                stok_path = tmp_path / "artifact.stok"
                stok_path.write_bytes(_b64d(body["stok_b64"]))
            else:
                _json_response(self, 400, {"error": "stok_path or stok_b64 required"})
                return

            key_path = None
            if body.get("key_path"):
                key_path = Path(body["key_path"])
            elif body.get("key_b64"):
                key_path = tmp_path / "artifact.stok.key"
                key_path.write_bytes(_b64d(body["key_b64"]))

            try:
                pt, info = open_artifact(
                    stok_path,
                    master_secret=master_b,
                    key_path=key_path,
                    update_friction=bool(body.get("update_friction", True)),
                )
                _json_response(
                    self,
                    200,
                    {
                        "recoverable": info.get("recoverable"),
                        "plaintext_b64": _b64e(pt) if pt is not None else None,
                        "info": {k: v for k, v in info.items() if k != "payload"},
                    },
                )
            except Exception as e:
                _json_response(
                    self,
                    500,
                    {"error": str(e), "traceback": traceback.format_exc()},
                )


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="ATL SmartTokenProd sidecar")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args(argv)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        f"ATL sidecar listening on http://{args.host}:{args.port}  "
        f"available={is_available()}  data={DATA_DIR}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("shutting down", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
