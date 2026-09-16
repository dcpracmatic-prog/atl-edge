"""HTTP surface for the reference Control Plane (src/control_plane.py).

Exposes exactly two customer-facing, unauthenticated-by-design* endpoints:

  POST /v1/activate   {api_key, node_id, instance_id, agent_id} -> SignedEntitlement
  GET  /v1/public-key -> Ed25519 public key, PEM

*"Unauthenticated" here means no separate auth header is required beyond
the API key itself — same as any bearer-token activation flow. License
*issuance* (`ControlPlane.issue_license`) is deliberately NOT exposed over
HTTP by this module: minting a new license is a back-office operation and
this reference server has no admin-auth layer to gate it safely. Wire
`ControlPlane.issue_license` into whatever already-authenticated admin
tool/billing webhook a real deployment has.
"""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from src.http_limits import BodyLimitError, REQUEST_SOCKET_TIMEOUT, read_bounded_body

from .control_plane import ControlPlane, LicenseError
from .dev_tls import server_context

logger = logging.getLogger("atl.control_plane")


class ControlPlaneServer:
    def __init__(self, control_plane: ControlPlane, *, host: str = "127.0.0.1", port: int = 0,
                 tls_certfile: Optional[Path] = None, tls_keyfile: Optional[Path] = None):
        self.control_plane = control_plane
        cp = control_plane

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                try:
                    self.connection.settimeout(REQUEST_SOCKET_TIMEOUT)
                except Exception:
                    pass

            def log_message(self, fmt, *args):
                logger.info("%s - %s", self.address_string(), fmt % args)

            def _json(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/v1/public-key":
                    self._json(200, {"public_key_pem": cp.public_key_pem().decode("ascii")})
                    return
                self._json(404, {"status": "NOT_FOUND"})

            def do_POST(self):
                if self.path != "/v1/activate":
                    self._json(404, {"status": "NOT_FOUND"})
                    return
                try:
                    raw = read_bounded_body(self.rfile, self.headers)
                except BodyLimitError as e:
                    self._json(413 if "too_large" in e.reason else 400, {"error": e.reason})
                    return
                try:
                    req = json.loads(raw.decode("utf-8"))
                    api_key = str(req["api_key"])
                    node_id = str(req["node_id"])
                    instance_id = str(req["instance_id"])
                    agent_id = str(req["agent_id"])
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    self._json(400, {"status": "BAD_REQUEST"})
                    return
                try:
                    signed = cp.activate(api_key, node_id=node_id, instance_id=instance_id, agent_id=agent_id)
                except LicenseError as exc:
                    logger.info("activation rejected node=%s: %s", node_id, exc)
                    # Deliberately generic to the network caller — same
                    # "no oracle" posture as ATLP/transport rejections.
                    self._json(403, {"status": "ACTIVATION_REJECTED"})
                    return
                self._json(200, {"payload": signed.payload, "signature": signed.signature})

        self._httpd = ThreadingHTTPServer((host, port), Handler)
        self.tls_enabled = bool(tls_certfile and tls_keyfile)
        if self.tls_enabled:
            ctx = server_context(Path(tls_certfile), Path(tls_keyfile))
            self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self._thread: Optional[threading.Thread] = None

    @property
    def url_scheme(self) -> str:
        return "https" if self.tls_enabled else "http"

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
