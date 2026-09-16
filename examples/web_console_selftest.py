#!/usr/bin/env python3
"""Secure-behavior selftest for the hardened ATL Edge operator console.

Checks (no attack PoCs):
  - 401 without Authorization bearer token (except GET /health)
  - no license / atl_live_ issuance endpoint
  - execute uses ATLDataPlaneMVP.production() (require_license + require_fields)
  - protect/open reject empty/default master_secret
  - destructive proposals REJECT
  - fields required
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.data_catalog import DataAsset, DataCatalog, NodeAccessPolicy, Sensitivity
from src.data_plane import LocalDataPlane, OnPremAuditLog, PackageCrypto
from src.edge_api_server import EdgeRuntime
from src.licensing import Entitlement
from src.mvp import ATLDataPlaneMVP
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.web_console import ConsoleState, make_console_handler


def _http(base: str, path: str, *, method: str = "GET", token: str | None = None,
          body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return exc.code, payload


def _build_runtime(tmp: Path) -> EdgeRuntime:
    # Lab-only keys for the selftest process. Never commit real secrets.
    master = hashlib.sha256(b"atl-console-selftest-master-not-for-prod").digest()
    node_id = "console-selftest-node"
    now = time.time()
    ent = Entitlement(
        license_id="lic-console-selftest",
        organization_id="org-selftest",
        plan="enterprise",
        issued_at=now - 60,
        expires_at=now + 3600,
        capabilities=("agent_access",),
        node_id=node_id,
        agent_id="agent-selftest",
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
    return EdgeRuntime(
        node_id=node_id,
        master=master,
        entitlement=ent,
        catalog=catalog,
        node_access=access,
        audit_path=tmp / "audit.jsonl",
    )


def main() -> int:
    token = "selftest-console-token-" + hashlib.sha256(b"atl").hexdigest()[:16]
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="atl-console-selftest-") as td:
        tmp = Path(td)
        os.environ["ATL_CONSOLE_TOKEN"] = token
        os.environ["ATL_DATA_DIR"] = str(tmp)
        os.environ["ATL_AUDIT_PATH"] = str(tmp / "audit.jsonl")
        os.environ["ATL_EXECUTION_LEDGER_PATH"] = str(tmp / "execution_ledger.sqlite")

        # The default production factory must fail closed without node/master/license.
        production_keys = (
            "ATL_ALLOW_DEV_DEFAULTS", "ATL_NODE_ID", "ATL_MASTER_KEY_HEX",
            "ATL_LICENSE_ID", "ATL_ORG_ID", "ATL_ENTITLEMENT_EXPIRES_AT",
            "ATL_ENTITLEMENT_PATH", "ATL_CONTROL_PLANE_PUBLIC_KEY_PATH",
        )
        saved = {key: os.environ.get(key) for key in production_keys}
        for key in production_keys:
            os.environ.pop(key, None)
        try:
            ConsoleState(tmp / "fail-closed", token=token)
            failures.append("default console runtime did not fail closed without production config")
        except RuntimeError:
            pass
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

        runtime = _build_runtime(tmp)
        assert isinstance(runtime.mvp, ATLDataPlaneMVP)
        assert runtime.mvp.require_license is True
        assert runtime.mvp.require_fields is True

        state = ConsoleState(tmp, token=token, runtime=runtime)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_console_handler(state))
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"

        try:
            # /health is public
            code, body = _http(base, "/health")
            if code != 200 or body.get("ok") is not True:
                failures.append(f"health expected 200 ok, got {code} {body}")

            # 401 without token on protected routes
            for path, method, payload in (
                ("/api/status", "GET", None),
                ("/api/work/execute", "POST", {"proposal": {}, "records": []}),
                ("/api/artifacts/protect", "POST", {"content": "x", "master_secret": ""}),
            ):
                code, body = _http(base, path, method=method, body=payload)
                if code != 401:
                    failures.append(f"{method} {path} without token expected 401, got {code}")

            # No license issuance endpoint (and no atl_live_ minting surface)
            code, body = _http(
                base,
                "/api/environments/license",
                method="POST",
                token=token,
                body={"org": "x", "plan": "enterprise"},
            )
            if code not in (404, 405):
                failures.append(f"license endpoint expected 404/405, got {code} {body}")
            blob = json.dumps(body)
            if "atl_live_" in blob:
                failures.append("license response unexpectedly contains atl_live_")

            # fields required
            code, body = _http(
                base,
                "/api/work/execute",
                method="POST",
                token=token,
                body={
                    "proposal": {
                        "schema_version": 1,
                        "tool": "lookup",
                        "operation": "read",
                        "resource": "crm",
                        "arguments": {},
                    },
                    "records": [{"customer_id": 1, "status": "active"}],
                },
            )
            if code != 400 or body.get("error") != "fields_required":
                failures.append(f"missing fields expected 400 fields_required, got {code} {body}")

            # destructive proposal REJECT
            code, body = _http(
                base,
                "/api/work/execute",
                method="POST",
                token=token,
                body={
                    "proposal": {
                        "schema_version": 1,
                        "tool": "lookup",
                        "operation": "delete",
                        "resource": "crm",
                        "fields": ["customer_id"],
                        "arguments": {},
                    },
                    "records": [{"customer_id": 1}],
                },
            )
            if code != 403 or body.get("decision") != "REJECT":
                failures.append(f"destructive expected REJECT/403, got {code} {body}")

            # happy-path execute through production()
            code, body = _http(
                base,
                "/api/work/execute",
                method="POST",
                token=token,
                body={
                    "proposal": {
                        "schema_version": 1,
                        "tool": "lookup",
                        "operation": "read",
                        "resource": "crm",
                        "fields": ["customer_id", "status"],
                        "arguments": {},
                    },
                    "records": [{"customer_id": 1, "status": "active"}],
                },
            )
            if code != 200 or body.get("ok") is not True or body.get("decision") not in ("ACCEPT", "REPAIR"):
                failures.append(f"execute happy path failed: {code} {body}")
            else:
                if not body.get("outbox", {}).get("package_bytes"):
                    failures.append("execute did not deposit sealed outbox package")
                if not state.mvp.require_license or not state.mvp.require_fields:
                    failures.append("execute path lost production() flags")

            # protect/open reject empty/default secrets (before any SmartToken call)
            for secret in ("", "default-secret", "changeme", "   "):
                code, body = _http(
                    base,
                    "/api/artifacts/protect",
                    method="POST",
                    token=token,
                    body={"content": "artifact", "master_secret": secret},
                )
                if code != 400 or body.get("error") != "master_secret_empty_or_default":
                    failures.append(f"protect secret={secret!r} expected reject, got {code} {body}")
                code, body = _http(
                    base,
                    "/api/artifacts/open",
                    method="POST",
                    token=token,
                    body={"artifact_id": "0" * 32, "master_secret": secret},
                )
                if code != 400 or body.get("error") != "master_secret_empty_or_default":
                    failures.append(f"open secret={secret!r} expected reject, got {code} {body}")

            # authenticated status
            code, body = _http(base, "/api/status", token=token)
            if code != 200 or body.get("production_path") is not True:
                failures.append(f"status failed: {code} {body}")

        finally:
            server.shutdown()
            server.server_close()

    if failures:
        print("web_console_selftest: FAIL")
        for f in failures:
            print(" -", f)
        return 1
    print(
        "web_console_selftest: PASS "
        "(401, no license endpoint, production execute, fields, destructive REJECT, secret reject)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
