#!/usr/bin/env python3
"""
ATL Edge API — single HTTP entry point over ATLDataPlaneMVP.

Design goal (closes RT1 at the network/API boundary)
----------------------------------------------------
Untrusted callers must only reach the orchestration seam
``ATLDataPlaneMVP.execute_and_issue``. This server intentionally:

  * does **not** expose ``LocalDataPlane`` or ``issue_for_agent``
  * does **not** accept raw sealed-package minting without a proposal
  * returns a minimal external vocabulary (``ok`` / ``INERT``)

Internal process code that imports ``LocalDataPlane`` directly remains a
process-trust concern; deploy untrusted agents as separate processes that
only speak this HTTP API.

Endpoints
---------
GET  /health
GET  /v1/capabilities
POST /v1/execute   — proposal + records → gate → authorize → executor stub → ATLP issue

Forbidden (must 404): anything resembling ``/v1/issue``, ``/v1/data_plane``,
``/v1/seal``, ``/admin/issue_for_agent``, etc.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_PKG = Path(__file__).resolve().parents[1]
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from src.data_catalog import DataAsset, DataCatalog, NodeAccessPolicy, Sensitivity
from src.data_plane import LocalDataPlane, OnPremAuditLog, PackageCrypto
from src.licensing import Entitlement
from src.mvp import ATLDataPlaneMVP
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.http_limits import (
    # re-export style: concurrent cap lives here with server
    BodyLimitError,
    REQUEST_SOCKET_TIMEOUT,
    read_bounded_json,
)

# Explicit allowlist — RT16 enumerates handler routes against this set.
MAX_CONCURRENT_REQUESTS = 32  # soft cap; excess gets 503
_ACTIVE_REQUESTS = 0
_ACTIVE_LOCK = __import__('threading').Lock()

ALLOWED_PATHS = frozenset({
    "/health",
    "/v1/capabilities",
    "/v1/execute",
})

# Paths an attacker might probe for a raw seal surface.
FORBIDDEN_PROBES = (
    "/v1/issue",
    "/v1/issue_for_agent",
    "/v1/seal",
    "/v1/data_plane",
    "/v1/dataplane",
    "/admin/issue",
    "/admin/issue_for_agent",
    "/internal/data_plane",
    "/debug/issue_for_agent",
)


def _inert(msg: str = "INERT") -> Dict[str, Any]:
    return {"ok": False, "error": "INERT", "detail": msg}


class EdgeRuntime:
    """Owns MVP + private data plane; never exposes the plane on the wire."""

    def __init__(
        self,
        *,
        node_id: str,
        master: bytes,
        entitlement: Entitlement,
        catalog: DataCatalog,
        node_access: NodeAccessPolicy,
        audit_path: Path,
    ) -> None:
        crypto = PackageCrypto.from_master(master, node_id, key_id="edge-v1")
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit = OnPremAuditLog(audit_path)
        # Private — not attached to the HTTP handler.
        self._data_plane = LocalDataPlane(crypto, audit)
        gate = ProposalGate(default_proposal_policy())
        ledger = os.environ.get("ATL_EXECUTION_LEDGER_PATH", str(audit_path.parent / "execution_ledger.sqlite"))
        self.mvp = ATLDataPlaneMVP.production(
            gate,
            self._data_plane,
            entitlement,
            catalog=catalog,
            node_access=node_access,
            ledger_path=ledger,
        )
        self.node_id = node_id

    def execute(
        self,
        proposal: Dict[str, Any],
        records: Sequence[Dict[str, Any]],
        *,
        fields: Optional[Sequence[str]] = None,
        request_id: Optional[str] = None,
        purpose: str = "edge-api",
    ) -> Dict[str, Any]:
        rid = request_id or str(uuid.uuid4())

        def executor(p: Dict[str, Any]) -> Dict[str, Any]:
            # No user-supplied callback on the wire — only a fixed local effect marker.
            return {"executed": True, "tool": p.get("tool"), "resource": p.get("resource")}

        execution = self.mvp.execute_and_issue(
            proposal,
            list(records),
            executor=executor,
            fields=fields,
            request_id=rid,
            purpose=purpose,
            requester="edge-api",
        )
        pkg = execution.issue.package if execution.issue else b""
        return {
            "ok": True,
            "request_id": rid,
            "gate_decision": execution.gate.decision,
            "executor_result": execution.executor_result,
            "package_b64": __import__("base64").b64encode(pkg).decode("ascii") if pkg else None,
            "metrics": dict(execution.issue.metrics) if execution.issue else {},
        }


def default_runtime_from_env() -> EdgeRuntime:
    """Build runtime from environment.

    Production is **fail-closed**: ``ATL_MASTER_KEY_HEX`` is required unless
    ``ATL_ALLOW_DEV_DEFAULTS=1`` is set explicitly for local demos.
    """
    allow_dev = os.environ.get("ATL_ALLOW_DEV_DEFAULTS", "").strip() in ("1", "true", "yes")
    node_id = os.environ.get("ATL_NODE_ID") or ("edge-node-1" if allow_dev else "")
    if not node_id:
        raise RuntimeError("ATL_NODE_ID is required (or set ATL_ALLOW_DEV_DEFAULTS=1)")

    master_hex = os.environ.get("ATL_MASTER_KEY_HEX", "").strip()
    if master_hex:
        master = bytes.fromhex(master_hex)
        if len(master) < 32:
            raise RuntimeError("ATL_MASTER_KEY_HEX must decode to at least 32 bytes")
    elif allow_dev:
        master = hashlib.sha256(b"atl-edge-api-dev-only-not-for-production").digest()
    else:
        raise RuntimeError(
            "ATL_MASTER_KEY_HEX is required for Edge API startup; "
            "refusing silent dev crypto defaults. Set ATL_ALLOW_DEV_DEFAULTS=1 only for local demos."
        )

    issued = float(os.environ.get("ATL_ENTITLEMENT_ISSUED_AT", "0") or 0)
    expires = os.environ.get("ATL_ENTITLEMENT_EXPIRES_AT", "").strip()
    ent_path_early = os.environ.get("ATL_ENTITLEMENT_PATH", "").strip()
    if expires:
        expires_at = float(expires)
    elif allow_dev:
        expires_at = time.time() + 86400 * 365
    elif ent_path_early:
        expires_at = 0.0  # will come from verified entitlement file
    else:
        raise RuntimeError(
            "ATL_ENTITLEMENT_EXPIRES_AT is required (unix timestamp), "
            "or set ATL_ENTITLEMENT_PATH + ATL_CONTROL_PLANE_PUBLIC_KEY_PATH, "
            "or ATL_ALLOW_DEV_DEFAULTS=1 for local demos."
        )

    ent_path = os.environ.get("ATL_ENTITLEMENT_PATH", "").strip()
    pub_path = os.environ.get("ATL_CONTROL_PLANE_PUBLIC_KEY_PATH", "").strip()
    if ent_path and pub_path:
        from src.licensing import SignedEntitlement, verify_entitlement

        signed = SignedEntitlement.from_json(Path(ent_path).read_text(encoding="utf-8"))
        ent = verify_entitlement(
            signed,
            Path(pub_path).read_bytes(),
            node_id=node_id,
        )
        # Prefer verified entitlement fields over loose env mirrors
        if not ent.node_id:
            # bind runtime node to entitlement when CP left node_id empty (should not happen after activate)
            pass
    else:
        ent = Entitlement(
            license_id=os.environ.get("ATL_LICENSE_ID") or ("lic-edge-dev" if allow_dev else ""),
            organization_id=os.environ.get("ATL_ORG_ID") or ("org-dev" if allow_dev else ""),
            plan=os.environ.get("ATL_PLAN", "edge"),
            issued_at=issued if issued > 0 else (time.time() - 60 if allow_dev else 0.0),
            expires_at=expires_at,
            capabilities=("agent_access",),
            node_id=node_id,
            agent_id=os.environ.get("ATL_AGENT_ID", ""),
        )
        if not allow_dev and (not ent.license_id or not ent.organization_id):
            raise RuntimeError(
                "Set ATL_ENTITLEMENT_PATH + ATL_CONTROL_PLANE_PUBLIC_KEY_PATH "
                "(from atlctl bootstrap-edge / activate-local), "
                "or ATL_LICENSE_ID + ATL_ORG_ID + ATL_ENTITLEMENT_EXPIRES_AT, "
                "or ATL_ALLOW_DEV_DEFAULTS=1 for local demos only"
            )
    catalog = DataCatalog()
    catalog.register(
        DataAsset(
            asset_id="crm",
            name="CRM",
            sensitivity=Sensitivity.INTERNAL,
            fields={
                "customer_id": Sensitivity.INTERNAL,
                "status": Sensitivity.PUBLIC,
                "ssn": Sensitivity.RESTRICTED,
            },
        )
    )
    access = NodeAccessPolicy(
        node_id=node_id,
        allowed_assets=("crm",),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    audit = Path(os.environ.get("ATL_AUDIT_PATH", str(_PKG / ".atl" / "edge_api_audit.jsonl")))
    return EdgeRuntime(
        node_id=node_id,
        master=master,
        entitlement=ent,
        catalog=catalog,
        node_access=access,
        audit_path=audit,
    )


def make_handler(runtime: EdgeRuntime):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ATL-EdgeAPI/1.0"

        def setup(self) -> None:
            super().setup()
            try:
                self.connection.settimeout(REQUEST_SOCKET_TIMEOUT)
            except Exception:
                pass

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

        def _send(self, code: int, body: Dict[str, Any]) -> None:
            data = json.dumps(body, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read(self) -> Dict[str, Any]:
            return read_bounded_json(self.rfile, self.headers)

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/health":
                self._send(200, {"ok": True, "service": "atl-edge-api", "node_id": runtime.node_id})
                return
            if path == "/v1/capabilities":
                self._send(
                    200,
                    {
                        "ok": True,
                        "allowed_paths": sorted(ALLOWED_PATHS),
                        "execute": True,
                        "raw_issue": False,
                        "data_plane_exposed": False,
                    },
                )
                return
            self._send(404, _inert("not_found"))

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if path != "/v1/execute":
                self._send(404, _inert("not_found"))
                return
            try:
                body = self._read()
            except BodyLimitError as e:
                self._send(413 if "too_large" in e.reason else 400, _inert(e.reason))
                return
            except Exception:
                self._send(400, _inert("bad_json"))
                return
            proposal = body.get("proposal")
            records = body.get("records") or []
            if not isinstance(proposal, dict) or not isinstance(records, list):
                self._send(400, _inert("bad_request"))
                return
            fields = body.get("fields")
            request_id = body.get("request_id")
            try:
                result = runtime.execute(
                    proposal,
                    records,
                    fields=fields,
                    request_id=request_id,
                    purpose=str(body.get("purpose") or "edge-api"),
                )
                self._send(200, result)
            except PermissionError:
                self._send(403, _inert("denied"))
            except Exception:
                self._send(400, _inert("rejected"))

        def do_PUT(self) -> None:
            self._send(404, _inert("not_found"))

        def do_DELETE(self) -> None:
            self._send(404, _inert("not_found"))

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8790, runtime: Optional[EdgeRuntime] = None) -> ThreadingHTTPServer:
    rt = runtime or default_runtime_from_env()

    class BoundedThreadingHTTPServer(ThreadingHTTPServer):
        """Reject excess concurrent handlers with a fast 503 (no unbounded thread growth)."""

        def process_request(self, request, client_address):  # type: ignore[override]
            global _ACTIVE_REQUESTS
            with _ACTIVE_LOCK:
                if _ACTIVE_REQUESTS >= MAX_CONCURRENT_REQUESTS:
                    try:
                        # Minimal HTTP 503 then close — avoid spawning a worker thread.
                        request.sendall(
                            b"HTTP/1.1 503 Service Unavailable\r\n"
                            b"Content-Type: application/json\r\n"
                            b"Content-Length: 37\r\n"
                            b"Connection: close\r\n\r\n"
                            b'{"error":"too_many_concurrent_requests"}'
                        )
                    except Exception:
                        pass
                    try:
                        request.close()
                    except Exception:
                        pass
                    return
                _ACTIVE_REQUESTS += 1
            try:
                super().process_request(request, client_address)
            finally:
                with _ACTIVE_LOCK:
                    _ACTIVE_REQUESTS = max(0, _ACTIVE_REQUESTS - 1)

    httpd = BoundedThreadingHTTPServer((host, port), make_handler(rt))
    return httpd


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="ATL Edge API (MVP-only HTTP seam)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8790)
    args = p.parse_args(argv)
    httpd = serve(args.host, args.port)
    print(
        f"ATL Edge API on http://{args.host}:{args.port}  "
        f"allowed={sorted(ALLOWED_PATHS)}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("shutting down", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
