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
import hmac
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
    BodyLimitError,
    REQUEST_SOCKET_TIMEOUT,
    read_bounded_json,
)

# Explicit allowlist — RT16 enumerates handler routes against this set.
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


EDGE_API_SECRET = os.environ.get("ATL_EDGE_API_SECRET", "")


def _inert(msg: str = "INERT") -> Dict[str, Any]:
    return {"ok": False, "error": "INERT", "detail": msg}


def dispatch_tool_execution(proposal: Dict[str, Any], records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Fixed local effect marker for accepted proposals.

    Deliberately does not branch on proposal-controlled fields (``tool``,
    ``operation``, ``arguments``) to process ``records``: doing so would let
    an untrusted caller drive real per-record logic (string transforms,
    filtering, "publish" flags) through the HTTP seam even after the gate
    accepts the proposal. MORPH-8 + the semantic policy already decided the
    proposal is allowed; this function only records that fact — it must not
    become a second, less-audited execution path. Real side effects belong
    behind ``ATLDataPlaneMVP.execute_and_issue``'s own executor contract,
    supplied by the deployment, not by attacker-controlled proposal content.
    """
    return {
        "executed": True,
        "tool": proposal.get("tool"),
        "resource": proposal.get("resource"),
    }


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
        gate = ProposalGate(default_proposal_policy())
        # The Data Plane receives only the gate's process-local issuance key;
        # raw issue_for_agent calls without a gate authorization are inert.
        self._data_plane = LocalDataPlane(crypto, audit, issue_auth_key=gate.issue_auth_key)
        self.mvp = ATLDataPlaneMVP.production(
            gate,
            self._data_plane,
            entitlement,
            catalog=catalog,
            node_access=node_access,
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
            return dispatch_tool_execution(p, records)

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
    node_id = os.environ.get("ATL_NODE_ID", "edge-node-1")
    master_hex = os.environ.get("ATL_MASTER_KEY_HEX", "")
    if master_hex:
        master = bytes.fromhex(master_hex)
    else:
        master = hashlib.sha256(b"atl-edge-api-dev-only-not-for-production").digest()
    ent = Entitlement(
        license_id=os.environ.get("ATL_LICENSE_ID", "lic-edge-dev"),
        organization_id=os.environ.get("ATL_ORG_ID", "org-dev"),
        plan="edge",
        issued_at=0.0,
        expires_at=time.time() + 86400 * 365,
        capabilities=("agent_access",),
        node_id=node_id,
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

        def _verify_auth(self) -> bool:
            secret = getattr(self.server, "edge_api_secret", EDGE_API_SECRET)
            if not secret:
                return True
            auth_header = self.headers.get("Authorization", "")
            token = ""
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
            elif "X-API-Key" in self.headers:
                token = self.headers.get("X-API-Key", "").strip()

            if not token:
                return False
            return hmac.compare_digest(token.encode("utf-8"), secret.encode("utf-8"))

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
            if not self._verify_auth():
                self._send(401, _inert("unauthorized"))
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
    httpd = ThreadingHTTPServer((host, port), make_handler(rt))
    return httpd


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="ATL Edge API (MVP-only HTTP seam)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8790)
    p.add_argument("--secret", default=os.environ.get("ATL_EDGE_API_SECRET", ""))
    args = p.parse_args(argv)
    rt = default_runtime_from_env()
    httpd = serve(args.host, args.port, runtime=rt)
    setattr(httpd, "edge_api_secret", args.secret)
    print(
        f"ATL Edge API on http://{args.host}:{args.port}  "
        f"allowed={sorted(ALLOWED_PATHS)}  auth={'enabled' if args.secret else 'disabled'}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("shutting down", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
