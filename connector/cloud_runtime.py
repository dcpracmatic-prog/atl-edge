"""Cloud Connector runtime.

Installed on the premium agent's cloud instance — NOT on the on-prem
physical node. The physical-node side is the **Edge**
(`src/data_plane.LocalDataPlane` + `src/file_workflow.Outbox`), which lives
beside the customer database. This module is the "conector en la instancia
del agente premium" from the product pitch: the one piece of ATL that
actually runs next to the paid agent and hands it decrypted, predigested
data.

Responsibilities, and nothing else:
  1. Accept authenticated pushes from an Edge (`src/transport.py`).
  2. Open each ATLP package with the Connector's own per-node key
     (`CloudDecryptConnector` — never the provisioning master key; see
     `data_plane.CloudDecryptConnector.from_env`).
  3. Hand the decrypted, already-predigested payload to the agent-side
     handler the deployment supplies (e.g. "call the premium agent with
     this JSON"). This runtime has no opinion about *which* premium agent
     API is on the other side of that handler.
  4. Never persist plaintext to disk.

This is a real, runnable HTTP server for the MVP, not a mock — see
`examples/e2e_edge_to_connector_selftest.py`. Out of scope for the MVP,
and belongs in front of this as a real reverse proxy / load balancer:
TLS termination, horizontal scaling, health checks, structured access
logs. The authentication itself (HMAC + nonce + ATLP AEAD) is real and
does not depend on TLS being present, though TLS should still front it in
production to keep headers/body off the wire in the clear.
"""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from src.data_plane import CloudDecryptConnector, ReplayCache, derive_transport_key
from src.dev_tls import server_context
from src.transport import NonceCache, verify_request, TIMESTAMP_HEADER, NONCE_HEADER, SIGNATURE_HEADER

logger = logging.getLogger("atl.connector")

AgentHandler = Callable[[str, str, Dict[str, Any]], None]  # (node_id, request_id, plaintext) -> None


class ConnectorIngestServer:
    """One HTTP server per Connector instance/node.

    Wraps ThreadingHTTPServer so the request-handling logic can close over
    per-instance state (transport key, nonce cache, decrypt context) without
    module-level globals, which the stdlib handler API otherwise forces.
    """

    def __init__(self, node_id: str, node_key_hex: str, on_package: AgentHandler, *,
                 host: str = "127.0.0.1", port: int = 0, key_id: str = "node-v1",
                 tls_certfile: Optional[Path] = None, tls_keyfile: Optional[Path] = None):
        node_key_bytes = bytes.fromhex(node_key_hex)
        if len(node_key_bytes) != 32:
            raise ValueError("node key must decode to 32 bytes")
        self.node_id = node_id
        self.transport_key = derive_transport_key(node_key_bytes)
        self.nonce_cache = NonceCache()
        self.decrypt = CloudDecryptConnector.from_node_key(
            node_key_bytes, node_id, key_id=key_id, replay=ReplayCache(),
            on_reject=lambda detail: logger.warning("atlp reject node=%s detail=%s", node_id, detail),
        )
        self.on_package = on_package
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                logger.info("%s - %s", self.address_string(), fmt % args)

            def do_POST(self):
                server._handle(self)

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

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        parts = handler.path.strip("/").split("/")
        if len(parts) != 3 or parts[0] != "ingest":
            handler.send_response(404)
            handler.end_headers()
            return
        _, req_node_id, request_id = parts
        length = int(handler.headers.get("Content-Length", "0") or "0")
        body = handler.rfile.read(length) if length > 0 else b""
        headers = {
            TIMESTAMP_HEADER: handler.headers.get(TIMESTAMP_HEADER, ""),
            NONCE_HEADER: handler.headers.get(NONCE_HEADER, ""),
            SIGNATURE_HEADER: handler.headers.get(SIGNATURE_HEADER, ""),
        }

        # Transport-layer auth first. Never distinguishes which check failed
        # to the network caller — mirrors ATLP's own INERT-only contract so
        # a network attacker gets no oracle either.
        try:
            if req_node_id != self.node_id:
                raise ValueError("node mismatch")
            verify_request(self.transport_key, "POST", handler.path, body, headers, self.nonce_cache)
        except Exception as exc:
            logger.warning("transport reject node=%s request=%s: %s", req_node_id, request_id, exc)
            self._respond(handler, 401, {"status": "REJECTED"})
            return

        # Payload-layer auth second (independent of transport auth): TTL,
        # node binding, AEAD tag, and ATLP's own replay cache.
        try:
            plaintext = self.decrypt.open_package(body)
        except ValueError:
            self._respond(handler, 422, {"status": "INERT"})
            return

        try:
            self.on_package(req_node_id, request_id, plaintext)
        except Exception:
            logger.exception("agent handler failed for request=%s", request_id)
            self._respond(handler, 500, {"status": "HANDLER_ERROR"})
            return

        self._respond(handler, 200, {"status": "ACCEPTED", "request_id": request_id})

    @staticmethod
    def _respond(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
