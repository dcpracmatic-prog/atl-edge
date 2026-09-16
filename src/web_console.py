#!/usr/bin/env python3
"""Authenticated, local-first operator console for ATL Edge.

The console is an administrative view over the hardened ``main`` runtime. Work
requests always pass through an ``ATLDataPlaneMVP.production()`` instance; this
module never exposes or calls ``LocalDataPlane.issue_for_agent`` directly.
License issuance deliberately remains in ``atlctl`` / the control plane.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sqlite3
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

_PKG = Path(__file__).resolve().parents[1]
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from src.edge_api_server import EdgeRuntime, default_runtime_from_env
from src.file_workflow import Inbox, Outbox
from src.http_limits import BodyLimitError, REQUEST_SOCKET_TIMEOUT, read_bounded_json
from src.long_lived_protection import (
    is_available as smarttoken_available,
    open_artifact,
    protect_artifact,
    status as smarttoken_status,
)
from src.sdk_provisioner import provision_bundle

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8795
_DESTRUCTIVE = frozenset({"delete", "shell", "exec", "drop", "truncate"})
_DEFAULT_SECRETS = frozenset({
    "default",
    "default-secret",
    "changeme",
    "change-me",
    "password",
    "secret",
    "master-secret",
    "clave-maestra-de-demostracion-2026",
})

INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ATL Edge Operator Console</title>
<style>
body{font:15px system-ui;background:#0d1117;color:#c9d1d9;max-width:1000px;margin:2rem auto;padding:0 1rem}
header,section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin:1rem 0}
h1,h2{color:#f0f6fc}input,textarea,button{font:inherit;padding:.55rem;margin:.3rem 0;background:#0d1117;color:#f0f6fc;border:1px solid #30363d;border-radius:5px}
textarea{width:97%;min-height:10rem}input{width:97%}button{background:#1f6feb;cursor:pointer}
pre{white-space:pre-wrap;overflow:auto;color:#7ee787}
</style></head><body>
<header><h1>ATL Edge Operator Console</h1>
<p>Local control surface. Execution uses the licensed production gate; this console cannot issue licenses.</p></header>
<section><h2>Operator authentication</h2>
<input id="token" type="password" autocomplete="off" placeholder="ATL_CONSOLE_TOKEN">
<button onclick="saveToken()">Use token</button><span id="auth"></span></section>
<section><h2>Status</h2><button onclick="callApi('/api/status')">Refresh</button>
<pre id="out">Enter the operator token, then refresh.</pre></section>
<section><h2>Execute proposal</h2>
<textarea id="payload">{"proposal":{"schema_version":1,"tool":"lookup","operation":"read","resource":"crm","fields":["customer_id","status"],"arguments":{}},"records":[{"customer_id":1,"status":"active"}]}</textarea>
<br><button onclick="execute()">Gate and execute</button></section>
<script>
const token=document.getElementById('token'), out=document.getElementById('out');
token.value=sessionStorage.getItem('atlConsoleToken')||'';
function saveToken(){sessionStorage.setItem('atlConsoleToken',token.value);document.getElementById('auth').textContent=' token held in this tab only';}
async function callApi(path,opts={}){
  const r=await fetch(path,{...opts,headers:{'Authorization':'Bearer '+token.value,'Content-Type':'application/json',...(opts.headers||{})}});
  const x=await r.json(); out.textContent=JSON.stringify(x,null,2); return x;
}
function execute(){callApi('/api/work/execute',{method:'POST',body:document.getElementById('payload').value})}
</script></body></html>
"""


def _safe_segment(value: Any, name: str) -> str:
    raw = str(value or "").strip()
    if not raw or Path(raw).name != raw or raw in (".", ".."):
        raise ValueError(f"invalid_{name}")
    return raw


def _valid_master_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    return len(normalized) >= 12 and normalized.casefold() not in _DEFAULT_SECRETS


def _destructive(proposal: Mapping[str, Any]) -> bool:
    def bad(value: Any) -> bool:
        return isinstance(value, str) and value.strip().casefold() in _DESTRUCTIVE

    if any(bad(proposal.get(k)) for k in ("tool", "operation", "action")):
        return True
    steps = proposal.get("steps", ())
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, Mapping) and any(bad(step.get(k)) for k in ("tool", "operation", "action")):
                return True
    return False


class ConsoleState:
    """State shared by HTTP handlers; defaults to the real fail-closed runtime."""

    def __init__(
        self,
        data_dir: Path,
        *,
        token: Optional[str] = None,
        runtime: Optional[EdgeRuntime] = None,
    ) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
        configured_token = token if token is not None else os.environ.get("ATL_CONSOLE_TOKEN", "")
        if not configured_token or not configured_token.strip():
            raise RuntimeError("ATL_CONSOLE_TOKEN is required and must be non-empty")
        self.token = configured_token

        # Prefer shared Edge durable paths when ATL_DATA_DIR is set.
        os.environ.setdefault("ATL_DATA_DIR", str(self.data_dir))
        os.environ.setdefault("ATL_AUDIT_PATH", str(self.data_dir / "audit.jsonl"))
        os.environ.setdefault(
            "ATL_EXECUTION_LEDGER_PATH",
            str(self.data_dir / "execution_ledger.sqlite"),
        )
        self.runtime = runtime if runtime is not None else default_runtime_from_env()
        self.mvp = self.runtime.mvp
        if not self.mvp.require_license or not self.mvp.require_fields:
            raise RuntimeError("console requires ATLDataPlaneMVP.production() safeguards")
        self.ledger_path = Path(os.environ["ATL_EXECUTION_LEDGER_PATH"])
        self.inbox = Inbox(self.data_dir / "inbox")
        self.outbox = Outbox(self.data_dir / "outbox")
        self.artifacts_dir = self.data_dir / "artifacts"
        self.connectors_dir = self.data_dir / "connectors"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.connectors_dir.mkdir(parents=True, exist_ok=True)
        for d in (self.artifacts_dir, self.connectors_dir):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

    @property
    def entitlement(self):
        return self.mvp.entitlement

    def status(self) -> Dict[str, Any]:
        ent = self.entitlement
        stp = smarttoken_status()
        return {
            "ok": True,
            "service": "atl-edge-console",
            "node_id": self.runtime.node_id,
            "license": {
                "status": "ACTIVE",
                "license_id": ent.license_id if ent else "",
                "organization_id": ent.organization_id if ent else "",
                "plan": ent.plan if ent else "",
                "expires_at": ent.expires_at if ent else None,
            },
            "production_path": bool(self.mvp.require_license and self.mvp.require_fields),
            "smarttoken": {
                "available": bool(stp.get("smart_token_prod_available")),
                "version": stp.get("version"),
                "native_friction_available": bool(stp.get("native_friction_available")),
            },
        }

    def resources(self) -> List[Dict[str, Any]]:
        catalog = self.mvp.catalog
        if catalog is None:
            return []
        result = []
        for asset_id in sorted(catalog.assets):
            asset = catalog.assets[asset_id]
            result.append(
                {
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "sensitivity": asset.sensitivity.name.lower(),
                    "fields": {k: v.name.lower() for k, v in sorted(asset.fields.items())},
                    "tags": list(asset.tags),
                }
            )
        return result

    def execute(self, body: Mapping[str, Any]) -> Dict[str, Any]:
        proposal = body.get("proposal")
        records = body.get("records")
        if (
            not isinstance(proposal, Mapping)
            or not isinstance(records, list)
            or any(not isinstance(x, dict) for x in records)
        ):
            raise ValueError("proposal_and_records_required")
        if _destructive(proposal):
            raise PermissionError("destructive_proposal_rejected")
        fields = body.get("fields") if "fields" in body else proposal.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(x, str) or not x.strip() for x in fields)
        ):
            raise ValueError("fields_required")
        ttl = body.get("ttl_seconds", 120)
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 600:
            raise ValueError("ttl_out_of_range")
        request_id = str(body.get("request_id") or uuid.uuid4())

        def executor(p: Dict[str, Any]) -> Dict[str, Any]:
            # Fixed effect marker only. Never accept shell/code/callbacks over HTTP.
            return {"executed": True, "tool": p.get("tool"), "resource": p.get("resource")}

        execution = self.mvp.execute_and_issue(
            proposal,
            records,
            executor=executor,
            fields=fields,
            request_id=request_id,
            requester="web-console",
            purpose=str(body.get("purpose") or "operator-console"),
            ttl_seconds=ttl,
        )
        if execution.issue is None:
            raise RuntimeError("issue_missing")
        issue = execution.issue
        entry = self.outbox.deposit(
            self.runtime.node_id,
            request_id,
            issue.package,
            policy_id=issue.header.policy_id,
            expiry=issue.header.expiry,
            created_at=issue.header.created_at,
        )
        return {
            "ok": True,
            "decision": execution.gate.decision,
            "request_id": request_id,
            "executor_result": execution.executor_result,
            "metrics": dict(issue.metrics),
            "outbox": {
                "package_bytes": entry.package_bytes,
                "package_sha256": entry.package_sha256,
                "expiry": entry.expiry,
            },
        }

    def ledger(self) -> List[Dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        conn = sqlite3.connect(str(self.ledger_path))
        try:
            rows = conn.execute(
                "SELECT request_id, state, updated_at FROM execution_ledger "
                "ORDER BY updated_at DESC LIMIT 200"
            ).fetchall()
            return [{"request_id": r[0], "state": r[1], "updated_at": r[2]} for r in rows]
        finally:
            conn.close()

    def list_outbox(self) -> List[Dict[str, Any]]:
        return [
            {
                "node_id": e.node_id,
                "request_id": e.request_id,
                "policy_id": e.policy_id,
                "expiry": e.expiry,
                "created_at": e.created_at,
                "package_bytes": e.package_bytes,
                "package_sha256": e.package_sha256,
            }
            for e in self.outbox.list_ready(self.runtime.node_id)
        ]

    def provision(self, body: Mapping[str, Any]) -> Dict[str, Any]:
        agent_id = _safe_segment(body.get("agent_id"), "agent_id")
        instance_id = _safe_segment(body.get("instance_id"), "instance_id")
        ent = self.entitlement
        manifest = {
            "organization_id": ent.organization_id if ent else "",
            "instance_id": instance_id,
            "node_id": self.runtime.node_id,
            "agent_id": agent_id,
            "skills": list(body.get("skills") or []),
            "transport": {"mode": "outbound"},
        }
        destination = self.connectors_dir / f"{agent_id}-{uuid.uuid4().hex[:8]}"
        out = provision_bundle(manifest, destination)
        return {"ok": True, "bundle": out.name, "credential_source": "node-secret-store"}

    def protect(self, body: Mapping[str, Any]) -> Dict[str, Any]:
        secret = body.get("master_secret")
        if not _valid_master_secret(secret):
            raise ValueError("master_secret_empty_or_default")
        content = body.get("content")
        content_b64 = body.get("content_b64")
        if isinstance(content, str):
            raw = content.encode("utf-8")
        elif isinstance(content_b64, str):
            try:
                raw = base64.b64decode(content_b64, validate=True)
            except Exception as exc:
                raise ValueError("content_b64_invalid") from exc
        else:
            raise ValueError("content_required")
        if len(raw) > 10 * 1024 * 1024:
            raise ValueError("artifact_too_large")
        if not smarttoken_available():
            raise RuntimeError("smarttoken_unavailable")
        artifact_id = uuid.uuid4().hex
        source = self.artifacts_dir / f".{artifact_id}.input"
        stok = self.artifacts_dir / f"{artifact_id}.stok"
        key = self.artifacts_dir / f"{artifact_id}.stok.key"
        source.write_bytes(raw)
        try:
            os.chmod(source, 0o600)
            stok_path, key_path = protect_artifact(
                source, master_secret=secret, output_path=stok, key_path=key
            )
        finally:
            source.unlink(missing_ok=True)
        return {
            "ok": True,
            "artifact_id": artifact_id,
            "stok_name": stok_path.name,
            "key_name": key_path.name,
        }

    def open(self, body: Mapping[str, Any]) -> Dict[str, Any]:
        secret = body.get("master_secret")
        if not _valid_master_secret(secret):
            raise ValueError("master_secret_empty_or_default")
        if not smarttoken_available():
            raise RuntimeError("smarttoken_unavailable")
        artifact_id = _safe_segment(body.get("artifact_id"), "artifact_id")
        if not all(c in "0123456789abcdef" for c in artifact_id) or len(artifact_id) != 32:
            raise ValueError("invalid_artifact_id")
        stok = self.artifacts_dir / f"{artifact_id}.stok"
        key = self.artifacts_dir / f"{artifact_id}.stok.key"
        if not stok.is_file() or not key.is_file():
            raise ValueError("artifact_not_found")
        plain, info = open_artifact(stok, master_secret=secret, key_path=key)
        result: Dict[str, Any] = {
            "ok": plain is not None,
            "artifact_id": artifact_id,
            "info": info,
        }
        if plain is not None:
            result["content_b64"] = base64.b64encode(plain).decode("ascii")
        return result


def make_console_handler(state: ConsoleState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ATL-Console/1.0"

        def setup(self) -> None:
            super().setup()
            try:
                self.connection.settimeout(REQUEST_SOCKET_TIMEOUT)
            except Exception:
                pass

        def log_message(self, fmt: str, *args: Any) -> None:
            # Request line/status only; bodies and Authorization are never logged.
            sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            expected = "Bearer " + state.token
            return secrets.compare_digest(header, expected)

        def _send_json(self, code: int, body: Mapping[str, Any]) -> None:
            raw = json.dumps(dict(body), default=str, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self) -> None:
            raw = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; frame-ancestors 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(raw)

        def _auth_or_401(self) -> bool:
            if self._authorized():
                return True
            self._send_json(401, {"ok": False, "error": "unauthorized"})
            return False

        def _read(self) -> Dict[str, Any]:
            return read_bounded_json(self.rfile, self.headers)

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/health":
                self._send_json(200, {"ok": True, "service": "atl-edge-console"})
                return
            if not self._auth_or_401():
                return
            if path == "/":
                self._send_html()
            elif path == "/api/status":
                self._send_json(200, state.status())
            elif path == "/api/resources":
                self._send_json(200, {"ok": True, "assets": state.resources()})
            elif path == "/api/work/ledger":
                self._send_json(200, {"ok": True, "records": state.ledger()})
            elif path == "/api/agents/outbox":
                self._send_json(200, {"ok": True, "packages": state.list_outbox()})
            else:
                self._send_json(404, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if not self._auth_or_401():
                return
            # License issuance is intentionally absent and reaches this 404.
            dispatch = {
                "/api/work/execute": state.execute,
                "/api/agents/provision": state.provision,
                "/api/artifacts/protect": state.protect,
                "/api/artifacts/open": state.open,
            }
            fn = dispatch.get(path)
            if fn is None:
                self._send_json(404, {"ok": False, "error": "not_found"})
                return
            try:
                body = self._read()
                result = fn(body)
                self._send_json(200, result)
            except BodyLimitError as exc:
                code = 413 if "too_large" in exc.reason else 400
                self._send_json(code, {"ok": False, "error": exc.reason})
            except PermissionError as exc:
                self._send_json(403, {"ok": False, "decision": "REJECT", "error": str(exc)})
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            except RuntimeError:
                self._send_json(503, {"ok": False, "error": "capability_unavailable"})
            except Exception:
                self._send_json(400, {"ok": False, "error": "rejected"})

        def do_PUT(self) -> None:
            if self._auth_or_401():
                self._send_json(404, {"ok": False, "error": "not_found"})

        def do_DELETE(self) -> None:
            if self._auth_or_401():
                self._send_json(404, {"ok": False, "error": "not_found"})

        def do_OPTIONS(self) -> None:
            if self._auth_or_401():
                self._send_json(404, {"ok": False, "error": "not_found"})

    return Handler


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    data_dir: Optional[Path] = None,
    state: Optional[ConsoleState] = None,
) -> ThreadingHTTPServer:
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    if host not in loopback_hosts and os.environ.get("ATL_CONSOLE_BIND_PUBLIC") != "1":
        raise RuntimeError(
            "non-loopback bind requires ATL_CONSOLE_BIND_PUBLIC=1 and TLS or host-level loopback isolation"
        )
    console_state = state or ConsoleState(
        data_dir or Path(os.environ.get("ATL_DATA_DIR", ".atl/edge-data"))
    )
    return ThreadingHTTPServer((host, port), make_console_handler(console_state))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ATL Edge authenticated operator console")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("ATL_DATA_DIR", ".atl/edge-data")),
    )
    args = parser.parse_args(argv)
    server = serve(args.host, args.port, data_dir=args.data_dir)
    print(
        f"ATL Edge console on http://{args.host}:{args.port} (Bearer auth required)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
