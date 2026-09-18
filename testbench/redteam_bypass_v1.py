#!/usr/bin/env python3
"""
ATL Hardened Red-Team v1 — execution-boundary bypass harness.

Hypothesis under test
---------------------
If a proposal does not traverse MORPH-8 + data authorization + license
(+ ATLP binding), it must produce neither a side-effect nor a valid package:

    ¬Authorized(proposal)  ⇒  ¬Effect ∧ ¬Issue
    Issue                  ⇒  Authorized ∧ Classified ∧ Licensed ∧ Bound

This harness does **not** trust happy-path self-tests. It actively attempts
bypass routes and records:

  - whether an effect was produced (executor ran)
  - whether an ATLP package was issued
  - whether data was exposed
  - the *external* observable response (oracle surface)
  - whether the attack is BLOCKED

Oracle resistance
-----------------
External responses are normalized to a small vocabulary (primarily INERT).
The harness compares external signatures across attack classes; excessive
distinctness is reported as ORACLE_LEAK (informational severity unless
combined with a real bypass).

Usage
-----
  PYTHONPATH=. python testbench/redteam_bypass_v1.py
  PYTHONPATH=. python testbench/redteam_bypass_v1.py --json testbench/redteam_report.json
  PYTHONPATH=. python testbench/redteam_bypass_v1.py --require-clean
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data_catalog import DataAsset, DataCatalog, NodeAccessPolicy, Sensitivity
from src.data_plane import LocalDataPlane, PackageCrypto, ReplayCache
from src.licensing import Entitlement
from src.mvp import ATLDataPlaneMVP
from src.proposal_gate import ProposalGate, default_proposal_policy


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class AttackResult:
    attack_id: str
    title: str
    category: str
    effect_produced: bool
    package_issued: bool
    data_exposed: bool
    external_code: str          # normalized observable to the "attacker"
    external_detail: str        # raw exception / message (internal diagnostic)
    blocked: bool
    oracle_signature: str       # stable hash of external shape only
    notes: str = ""
    duration_ms: float = 0.0

    @property
    def status(self) -> str:
        # Control baseline is expected to produce effect + package.
        if self.attack_id == "RT0":
            if self.effect_produced and self.package_issued:
                return "PASS"
            return "FAIL"
        if not self.blocked and (self.effect_produced or self.package_issued or self.data_exposed):
            return "BYPASS"
        if not self.blocked:
            return "UNEXPECTED"
        return "BLOCK"


@dataclass
class RedTeamReport:
    started: str
    finished: str
    results: List[AttackResult] = field(default_factory=list)
    oracle_classes: Dict[str, List[str]] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Fixture: production-like MVP stack
# ---------------------------------------------------------------------------

NODE_ID = "node-redteam-1"
MASTER = hashlib.sha256(b"atl-redteam-master-not-for-production").digest()


def _make_entitlement(
    *,
    node_id: str = NODE_ID,
    capabilities: Sequence[str] = ("agent_access",),
    license_id: str = "lic-redteam-1",
) -> Entitlement:
    return Entitlement(
        license_id=license_id,
        organization_id="org-redteam",
        plan="redteam",
        issued_at=0.0,
        expires_at=time.time() + 3600,
        max_nodes=1,
        max_agents=4,
        capabilities=tuple(capabilities),
        node_id=node_id,
    )


def build_stack(
    *,
    require_license: bool = True,
    entitlement: Optional[Entitlement] = None,
    max_sensitivity: Sensitivity = Sensitivity.CONFIDENTIAL,
    allowed_assets: Sequence[str] = ("crm",),
) -> Tuple[ATLDataPlaneMVP, LocalDataPlane, ProposalGate, PackageCrypto]:
    crypto = PackageCrypto.from_master(MASTER, NODE_ID, key_id="node-v1")
    from src.data_plane import OnPremAuditLog

    audit_path = ROOT / ".atl" / "redteam_audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit = OnPremAuditLog(audit_path)
    dp = LocalDataPlane(crypto, audit)
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
        node_id=NODE_ID,
        allowed_assets=tuple(allowed_assets),
        max_sensitivity=max_sensitivity,
    )
    gate = ProposalGate(default_proposal_policy())
    ent = entitlement if entitlement is not None else _make_entitlement()
    mvp = ATLDataPlaneMVP(
        gate,
        dp,
        catalog=catalog,
        node_access=access,
        entitlement=ent,
        require_license=require_license,
    )
    return mvp, dp, gate, crypto


VALID_PROPOSAL = {
    "schema_version": 1,
    "tool": "lookup",
    "operation": "read",
    "resource": "crm",
    "fields": ["customer_id", "status"],
    "arguments": {"status": "active"},
}

RECORDS = [{"customer_id": i, "status": "active", "ssn": f"000-00-{i:04d}"} for i in range(5)]


def _normalize_external(exc: BaseException | None, effect: bool, issued: bool) -> Tuple[str, str, str]:
    """Map internal outcomes to attacker-visible vocabulary."""
    if effect or issued:
        detail = "EFFECT" if effect else "ISSUED"
        return "SUCCESS", detail, hashlib.sha256(detail.encode()).hexdigest()[:12]

    if exc is None:
        return "INERT", "none", hashlib.sha256(b"INERT:none").hexdigest()[:12]

    # Collapse permission / schema / policy failures to a single external code.
    # Keep the raw message only as internal diagnostic (not part of oracle sig).
    name = type(exc).__name__
    msg = str(exc)
    if isinstance(exc, PermissionError):
        code = "INERT"
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        code = "INERT"
    else:
        code = "INERT"
    # Oracle signature intentionally ignores the specific reason string.
    sig = hashlib.sha256(f"{code}|{name}".encode()).hexdigest()[:12]
    return code, f"{name}: {msg}", sig


def _run_attack(
    attack_id: str,
    title: str,
    category: str,
    fn: Callable[[], Tuple[bool, bool, bool, Optional[BaseException], str]],
) -> AttackResult:
    t0 = time.perf_counter()
    try:
        effect, issued, exposed, exc, notes = fn()
    except Exception as e:  # harness must never crash the suite
        effect, issued, exposed, exc, notes = False, False, False, e, "harness-exception"
    dt = (time.perf_counter() - t0) * 1000
    code, detail, sig = _normalize_external(exc, effect, issued)
    blocked = not (effect or issued or exposed)
    return AttackResult(
        attack_id=attack_id,
        title=title,
        category=category,
        effect_produced=effect,
        package_issued=issued,
        data_exposed=exposed,
        external_code=code,
        external_detail=detail,
        blocked=blocked,
        oracle_signature=sig,
        notes=notes,
        duration_ms=round(dt, 3),
    )


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------

def attack_legitimate_baseline() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """Control: legitimate path MUST produce effect + package (sanity)."""
    mvp, _, _, _ = build_stack()
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return {"ok": True, "tool": p.get("tool")}

    try:
        ex = mvp.execute_and_issue(
            VALID_PROPOSAL, RECORDS, executor=executor,
            fields=["customer_id", "status"], request_id="rt-legit-1",
        )
        issued = ex.issue is not None
        exposed = bool(ex.issue and getattr(ex.issue, "package", None) is not None)
        return flag["ran"], issued, exposed, None, "baseline"
    except Exception as e:
        return flag["ran"], False, False, e, "baseline-failed"


def attack_morph_bypass_direct_executor() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """Call executor without going through MVP (application-level convention).

    Note: pure Python cannot prevent a malicious caller from invoking a local
    function. This attack documents that the *orchestration seam* is the
    boundary; if callers invoke executors directly, that is outside ATL.
    The harness verifies MVP does not expose a side channel that issues packages
    without gate.check().
    """
    mvp, dp, gate, crypto = build_stack()
    # Attempt to issue via data_plane directly without gate
    try:
        issue = dp.issue_for_agent(
            RECORDS,
            policy_id="forged",
            ttl_seconds=60,
            fields=["customer_id"],
            requester="attacker",
            purpose="bypass",
            request_id="rt-morph-bypass-1",
            policy_hash="0" * 64,
            proposal_hash="0" * 64,
            result_manifest_hash="",
            license_id="",
        )
        # Direct data-plane issue is possible if caller has the object —
        # this is an acknowledged trust boundary: process integrity.
        # Red-team records it; production must not hand DataPlane to untrusted code.
        return False, issue is not None, issue is not None, None, "direct-dataplane-issue"
    except Exception as e:
        return False, False, False, e, "direct-dataplane-blocked"


def attack_morph_reject_bad_tool() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, _, _, _ = build_stack()
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    bad = dict(VALID_PROPOSAL)
    bad["tool"] = "shell"
    bad["operation"] = "exec"
    try:
        mvp.execute_and_issue(bad, RECORDS, executor=executor, request_id="rt-morph-tool")
        return flag["ran"], True, True, None, "should-have-blocked"
    except Exception as e:
        return flag["ran"], False, False, e, "morph-or-policy"


def attack_mutation_after_gate() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """MORPH accepts; attacker mutates proposal dict before executor.

    The gate returns a normalized proposal; MVP must execute the gated copy,
    not a caller-mutated original. We mutate the input after check by interposing.
    """
    mvp, _, gate, _ = build_stack()
    original = dict(VALID_PROPOSAL)
    gr = gate.check(original)
    if not gr.allowed:
        return False, False, False, PermissionError(gr.reason), "gate-rejected-valid"

    # Mutate the *caller's* mapping after a successful check
    original["operation"] = "delete"
    original["resource"] = "secrets"
    flag = {"ran": False, "saw": None}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        flag["saw"] = dict(p)
        return p

    try:
        # Re-enter full path with mutated proposal — must be rejected by gate
        mvp.execute_and_issue(original, RECORDS, executor=executor, request_id="rt-mut-1")
        # If accepted, check whether executor saw the dangerous mutation
        dangerous = flag["saw"] and (
            flag["saw"].get("operation") == "delete" or flag["saw"].get("resource") == "secrets"
        )
        return flag["ran"], True, dangerous, None, "mutation-accepted"
    except Exception as e:
        return flag["ran"], False, False, e, "mutation-blocked"


def attack_data_field_escalation() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, _, _, _ = build_stack(max_sensitivity=Sensitivity.INTERNAL)
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    prop = dict(VALID_PROPOSAL)
    prop["fields"] = ["customer_id", "status", "ssn"]  # RESTRICTED
    try:
        mvp.execute_and_issue(
            prop, RECORDS, executor=executor, fields=["ssn"], request_id="rt-data-ssn"
        )
        return flag["ran"], True, True, None, "ssn-exposed"
    except Exception as e:
        return flag["ran"], False, False, e, "data-auth"


def attack_data_wrong_resource() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, _, _, _ = build_stack()
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    prop = dict(VALID_PROPOSAL)
    prop["resource"] = "hr_salary"
    try:
        mvp.execute_and_issue(prop, RECORDS, executor=executor, request_id="rt-data-res")
        return flag["ran"], True, True, None, "wrong-asset"
    except Exception as e:
        return flag["ran"], False, False, e, "data-auth"


def attack_license_missing() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    try:
        mvp, _, _, _ = build_stack(require_license=True, entitlement=None)
    except Exception as e:
        return False, False, False, e, "construct"
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    try:
        # force entitlement None after construct
        mvp.entitlement = None
        mvp.execute_and_issue(VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-lic-none")
        return flag["ran"], True, True, None, "no-license"
    except Exception as e:
        return flag["ran"], False, False, e, "license"


def attack_license_wrong_capability() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    ent = _make_entitlement(capabilities=("billing_only",))
    try:
        mvp, _, _, _ = build_stack(entitlement=ent)
    except PermissionError as e:
        return False, False, False, e, "construct-denied"
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    try:
        mvp.execute_and_issue(VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-lic-cap")
        return flag["ran"], True, True, None, "bad-capability"
    except Exception as e:
        return flag["ran"], False, False, e, "license"


def attack_license_wrong_node() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    ent = _make_entitlement(node_id="node-OTHER")
    try:
        mvp, _, _, _ = build_stack(entitlement=ent)
    except PermissionError as e:
        return False, False, False, e, "construct-denied"
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    try:
        mvp.execute_and_issue(VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-lic-node")
        return flag["ran"], True, True, None, "node-mismatch"
    except Exception as e:
        return flag["ran"], False, False, e, "license"


def attack_duplicate_request_id() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, _, _, _ = build_stack()
    runs = {"n": 0}

    def executor(p):  # noqa: ANN001
        runs["n"] += 1
        return p

    mvp.execute_and_issue(
        VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-dup-1"
    )
    try:
        mvp.execute_and_issue(
            VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-dup-1"
        )
        return runs["n"] > 1, True, True, None, "duplicate-accepted"
    except Exception as e:
        return runs["n"] > 1, False, False, e, "dup"


def attack_concurrent_same_request_id() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, _, _, _ = build_stack()
    success = {"n": 0}
    lock = threading.Lock()

    def executor(p):  # noqa: ANN001
        time.sleep(0.05)
        return p

    def one():
        try:
            mvp.execute_and_issue(
                VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-conc-1"
            )
            with lock:
                success["n"] += 1
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = [pool.submit(one) for _ in range(16)]
        for f in as_completed(futs):
            f.result()

    # More than one success is a concurrency bypass
    bypass = success["n"] > 1
    if bypass:
        return True, True, True, None, f"concurrent-successes={success['n']}"
    # Exactly one success is correct; treat as blocked attack (no *extra* effect)
    return False, False, False, PermissionError("single-winner"), f"successes={success['n']}"


def attack_atlp_open_wrong_node() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, dp, _, crypto = build_stack()

    def executor(p):  # noqa: ANN001
        return p

    ex = mvp.execute_and_issue(
        VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-atlp-node"
    )
    pkg = ex.issue.package
    other = PackageCrypto.from_master(MASTER, "node-OTHER", key_id="node-v1")
    try:
        other.open(pkg)
        return False, True, True, None, "wrong-node-opened"
    except Exception as e:
        return False, False, False, e, "atlp-node"



def attack_atlp_replay_open() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, dp, _, crypto = build_stack()

    def executor(p):  # noqa: ANN001
        return p

    ex = mvp.execute_and_issue(
        VALID_PROPOSAL, RECORDS, executor=executor, request_id="rt-replay-1"
    )
    pkg = ex.issue.package
    try:
        crypto.open(pkg)
        try:
            crypto.open(pkg)
            return False, True, True, None, "replay-accepted"
        except Exception as e:
            return False, False, False, e, "replay-blocked"
    except Exception as e:
        return False, False, False, e, "first-open-failed"



def attack_fault_truncated_proposal() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, _, _, _ = build_stack()
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    try:
        mvp.execute_and_issue("not-a-dict", RECORDS, executor=executor, request_id="rt-fault-1")  # type: ignore
        return flag["ran"], True, True, None, "accepted-garbage"
    except Exception as e:
        return flag["ran"], False, False, e, "fault"


def attack_composition_morph_fail_data_ok() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """MORPH/policy FAIL — must not reach data/executor even if data would pass."""
    mvp, _, _, _ = build_stack()
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    prop = dict(VALID_PROPOSAL)
    prop["tool"] = "shell"
    try:
        mvp.execute_and_issue(prop, RECORDS, executor=executor, request_id="rt-comp-1")
        return flag["ran"], True, True, None, "comp-fail"
    except Exception as e:
        return flag["ran"], False, False, e, "comp"


def attack_composition_data_fail_license_ok() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    mvp, _, _, _ = build_stack(max_sensitivity=Sensitivity.PUBLIC)
    flag = {"ran": False}

    def executor(p):  # noqa: ANN001
        flag["ran"] = True
        return p

    # customer_id is INTERNAL — should fail under PUBLIC max
    try:
        mvp.execute_and_issue(
            VALID_PROPOSAL, RECORDS, executor=executor,
            fields=["customer_id"], request_id="rt-comp-2",
        )
        return flag["ran"], True, True, None, "comp-fail"
    except Exception as e:
        return flag["ran"], False, False, e, "comp"



def attack_edge_api_no_raw_issue_surface() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """RT16 — HTTP Edge API must not expose data_plane / issue_for_agent.

    Starts ``edge_api_server`` in-process, probes forbidden paths, and verifies
    that the only productive route is POST /v1/execute (MVP seam).
    """
    import base64
    import json
    import threading
    import urllib.error
    import urllib.request
    from src.edge_api_server import (
        ALLOWED_PATHS,
        FORBIDDEN_PROBES,
        default_runtime_from_env,
        serve,
    )

    httpd = serve("127.0.0.1", 0, runtime=default_runtime_from_env())
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"

    def get(path: str) -> Tuple[int, dict]:
        req = urllib.request.Request(base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            try:
                return e.code, json.loads(body)
            except Exception:
                return e.code, {"raw": body}

    def post(path: str, payload: dict) -> Tuple[int, dict]:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            base + path, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            try:
                return e.code, json.loads(body)
            except Exception:
                return e.code, {"raw": body}

    try:
        # Capabilities must advertise no raw issue
        code, caps = get("/v1/capabilities")
        if code != 200 or caps.get("raw_issue") or caps.get("data_plane_exposed"):
            return True, True, True, None, "capabilities-leak"

        # Forbidden probes must not succeed
        for path in FORBIDDEN_PROBES:
            for method in ("GET", "POST"):
                if method == "GET":
                    c, body = get(path)
                else:
                    c, body = post(path, {"records": RECORDS})
                if c == 200 and body.get("ok") is True:
                    return True, True, True, None, f"forbidden-open:{path}"
                if c == 200 and (body.get("package_b64") or body.get("package")):
                    return True, True, True, None, f"forbidden-package:{path}"

        # Legitimate execute works
        c, body = post(
            "/v1/execute",
            {
                "proposal": VALID_PROPOSAL,
                "records": RECORDS,
                "fields": ["customer_id", "status"],
                "request_id": "rt16-ok",
            },
        )
        if c != 200 or not body.get("ok") or not body.get("package_b64"):
            return False, False, False, RuntimeError(str(body)), "execute-failed"

        # Denied tool via HTTP must not issue
        c2, body2 = post(
            "/v1/execute",
            {
                "proposal": {**VALID_PROPOSAL, "tool": "shell", "operation": "exec"},
                "records": RECORDS,
                "request_id": "rt16-deny",
            },
        )
        if c2 == 200 and body2.get("ok"):
            return True, True, True, None, "http-morph-bypass"

        # Handler allowlist equals documented set
        if set(caps.get("allowed_paths") or []) != set(ALLOWED_PATHS):
            return True, False, False, None, "allowlist-drift"

        # Attack blocked: no raw issue surface on the wire
        return False, False, False, PermissionError("no-raw-issue-surface"), "edge-api-sealed"
    finally:
        httpd.shutdown()




def attack_content_length_dos() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """RT17 — Lying Content-Length must not hang the Edge API worker.

    Sends Content-Length far above the server limit with an empty body.
    A vulnerable handler blocks on rfile.read(huge). Hardened handler rejects
    with 413/400 without stalling past a short deadline.
    """
    import socket
    import threading
    import time
    from src.edge_api_server import default_runtime_from_env, serve
    from src.http_limits import MAX_BODY_BYTES

    httpd = serve("127.0.0.1", 0, runtime=default_runtime_from_env())
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        # 1) Declared length >> max, no body bytes → must reject quickly
        t0 = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.settimeout(3)
        huge = MAX_BODY_BYTES * 50
        req = (
            f"POST /v1/execute HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {huge}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        s.sendall(req)
        # Do not send body — vulnerable server blocks; hardened returns 413.
        chunks = []
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        except socket.timeout:
            elapsed = time.perf_counter() - t0
            s.close()
            # Hung past deadline = DoS still open
            return True, False, False, None, f"hung:{elapsed:.2f}s"
        s.close()
        elapsed = time.perf_counter() - t0
        resp = b"".join(chunks).decode("latin-1", errors="replace")
        if elapsed > 2.5:
            return True, False, False, None, f"slow-reject:{elapsed:.2f}s"
        if "413" in resp.split("\r\n", 1)[0] or "400" in resp.split("\r\n", 1)[0]:
            # Server still responsive after attack
            s2 = socket.create_connection(("127.0.0.1", port), timeout=3)
            s2.settimeout(3)
            s2.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            health = s2.recv(1024).decode("latin-1", errors="replace")
            s2.close()
            if "200" not in health.split("\r\n", 1)[0]:
                return True, False, False, None, "health-dead-after-attack"
            return False, False, False, PermissionError("cl-rejected"), "content-length-bounded"
        return True, False, False, None, f"unexpected-resp:{resp[:80]!r}"
    finally:
        httpd.shutdown()




def attack_slow_drip_body() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """RT18 — Slow-drip body must hit absolute deadline, not only idle timeout.

    A peer that sends 1 byte just under REQUEST_SOCKET_TIMEOUT can keep a
    naive read(n) alive for hours. read_bounded_body must abort via
    BODY_READ_DEADLINE_SECONDS even when the per-socket idle timer never fires.
    """
    import io
    import time
    from src.http_limits import BodyLimitError, read_bounded_body

    class DripRfile(io.RawIOBase):
        """Yields 1 byte every ~0.05s; idle gaps stay under a typical socket timeout."""

        def __init__(self, total: int, pause: float = 0.05):
            super().__init__()
            self._left = total
            self._pause = pause

        def readable(self) -> bool:
            return True

        def read(self, size: int = -1) -> bytes:
            if self._left <= 0:
                return b""
            time.sleep(self._pause)
            self._left -= 1
            return b"x"

        def read1(self, size: int = -1) -> bytes:
            return self.read(1 if size < 0 else max(1, min(size, 1)))

    # BufferedReader-like wrapper exposing read1
    class Wrap:
        def __init__(self, raw):
            self._raw = raw

        def read(self, n: int) -> bytes:
            return self._raw.read(n)

        def read1(self, n: int) -> bytes:
            return self._raw.read1(n)

    headers = {"Content-Length": "100000"}  # within MAX, but slow
    rfile = Wrap(DripRfile(100000, pause=0.05))
    t0 = time.perf_counter()
    try:
        read_bounded_body(rfile, headers, max_bytes=100000, deadline_seconds=0.4)
        elapsed = time.perf_counter() - t0
        return True, False, False, None, f"drip-accepted:{elapsed:.2f}s"
    except BodyLimitError as e:
        elapsed = time.perf_counter() - t0
        if e.reason != "body_read_deadline":
            return True, False, False, e, f"wrong-reason:{e.reason}"
        if elapsed > 2.0:
            return True, False, False, None, f"deadline-too-slow:{elapsed:.2f}s"
        return False, False, False, e, "slow-drip-deadline"
    except Exception as e:
        return True, False, False, e, "unexpected"



def attack_egress_tool_sweep() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """Every egress-flavoured tool name must be rejected, with no package issued.

    RT2 already proves one name ("shell") is refused. That is not the same claim.
    The product claim is that the node initiates NOTHING, so what has to hold is
    that the whole family is unreachable -- premium, http, openai, webhook,
    subprocess and the rest -- and that each rejection leaves no executor run and
    no sealed package behind. A single name passing here falsifies the sales
    sheet, not just a test.
    """
    from src.egress_invariant import FORBIDDEN_TOOL_NAMES

    mvp, _, _, _ = build_stack()
    ran: List[str] = []
    issued: List[str] = []

    for i, name in enumerate(FORBIDDEN_TOOL_NAMES):
        flag = {"ran": False}

        def executor(p, _f=flag):  # noqa: ANN001
            _f["ran"] = True
            return p

        bad = dict(VALID_PROPOSAL)
        bad["tool"] = name
        try:
            mvp.execute_and_issue(
                bad, RECORDS, executor=executor, request_id=f"rt-egress-tool-{i}"
            )
            issued.append(name)  # got a package out: bypass
        except Exception:
            pass
        if flag["ran"]:
            ran.append(name)

    if issued or ran:
        return (
            bool(ran),
            bool(issued),
            bool(issued),
            None,
            f"egress-tool-admitted:issued={issued}:ran={ran}",
        )
    return False, False, False, None, f"egress-tools-all-rejected:{len(FORBIDDEN_TOOL_NAMES)}"


def attack_egress_client_on_sealing_path() -> Tuple[bool, bool, bool, Optional[BaseException], str]:
    """No module on the sealing path may import an outbound client.

    The gate can only reject tool *names*. It cannot stop code from opening a
    socket directly, so rejecting "http" proves nothing on its own if
    result_packaging.py quietly grew an `import requests`. This checks the
    capability is absent from the files that turn a proposal into a package.
    """
    from src.egress_invariant import (
        EGRESS_MODULES,
        GUARDED_SOURCES,
        scan_sources_for_egress,
    )

    try:
        findings = scan_sources_for_egress()
    except Exception as e:
        return False, False, False, e, "invariant-scan-failed"

    if findings:
        return (
            True,
            False,
            True,
            None,
            "egress-client-present:" + ";".join(str(f) for f in findings),
        )
    return (
        False,
        False,
        False,
        None,
        f"no-egress-client:{len(GUARDED_SOURCES)}files/{len(EGRESS_MODULES)}modules",
    )


ATTACKS: List[Tuple[str, str, str, Callable]] = [
    ("RT0", "Legitimate baseline (control)", "control", attack_legitimate_baseline),
    ("RT1", "Direct DataPlane issue without gate", "morph", attack_morph_bypass_direct_executor),
    ("RT2", "Denied tool/operation via MVP", "morph", attack_morph_reject_bad_tool),
    ("RT3", "Mutation after conceptual gate", "mutation", attack_mutation_after_gate),
    ("RT4", "Field escalation to SSN", "data", attack_data_field_escalation),
    ("RT5", "Unauthorized resource", "data", attack_data_wrong_resource),
    ("RT6", "Missing license entitlement", "license", attack_license_missing),
    ("RT7", "Wrong license capability", "license", attack_license_wrong_capability),
    ("RT8", "License node mismatch", "license", attack_license_wrong_node),
    ("RT9", "Duplicate request_id", "concurrency", attack_duplicate_request_id),
    ("RT10", "Concurrent same request_id (16 workers)", "concurrency", attack_concurrent_same_request_id),
    ("RT11", "ATLP open with wrong node key", "atlp", attack_atlp_open_wrong_node),
    ("RT12", "ATLP replay second open", "atlp", attack_atlp_replay_open),
    ("RT13", "Fault: non-dict proposal", "fault", attack_fault_truncated_proposal),
    ("RT14", "Composition: MORPH fail / data would pass", "composition", attack_composition_morph_fail_data_ok),
    ("RT15", "Composition: data fail / license ok", "composition", attack_composition_data_fail_license_ok),
    ("RT16", "Edge API: no HTTP raw issue_for_agent / data_plane", "api-boundary", attack_edge_api_no_raw_issue_surface),
    ("RT17", "Lying Content-Length DoS on Edge API", "api-dos", attack_content_length_dos),
    ("RT18", "Slow-drip body vs absolute read deadline", "api-dos", attack_slow_drip_body),
    ("RT19", "Egress tool sweep (premium/http/openai/shell/...)", "egress", attack_egress_tool_sweep),
    ("RT20", "Outbound client on the sealing path", "egress", attack_egress_client_on_sealing_path),
]


def run_redteam() -> RedTeamReport:
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    results: List[AttackResult] = []
    for aid, title, cat, fn in ATTACKS:
        results.append(_run_attack(aid, title, cat, fn))
    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Oracle clustering: group attack_ids by external signature (exclude control success)
    oracle: Dict[str, List[str]] = {}
    for r in results:
        if r.attack_id == "RT0":
            continue
        oracle.setdefault(r.oracle_signature, []).append(r.attack_id)

    bypasses = [r for r in results if r.status == "BYPASS"]
    # RT1 is a known process-trust finding if it issues: count separately
    known = [r for r in bypasses if r.attack_id == "RT1"]
    unknown = [r for r in bypasses if r.attack_id != "RT1"]

    report = RedTeamReport(
        started=started,
        finished=finished,
        results=results,
        oracle_classes=oracle,
        summary={
            "total": len(results),
            "blocked": sum(1 for r in results if r.status == "BLOCK"),
            "bypass": len(bypasses),
            "known_process_trust_findings": len(known),
            "unknown_bypasses": len(unknown),
            "oracle_distinct_signatures": len(oracle),
            "control_baseline_ok": any(
                r.attack_id == "RT0" and r.effect_produced and r.package_issued for r in results
            ),
            "clean": len(unknown) == 0
            and any(r.attack_id == "RT0" and r.effect_produced for r in results),
        },
    )
    return report


def render_matrix(report: RedTeamReport) -> str:
    lines = [
        "# ATL Hardened Red-Team v1 — Results Matrix",
        "",
        f"Started: `{report.started}`  ",
        f"Finished: `{report.finished}`",
        "",
        "| Attack | Effect | Package | Data exposed | External | Status | Notes |",
        "|--------|:------:|:-------:|:------------:|----------|--------|-------|",
    ]
    for r in report.results:
        lines.append(
            f"| {r.attack_id} {r.title} | {'YES' if r.effect_produced else 'NO'} | "
            f"{'YES' if r.package_issued else 'NO'} | {'YES' if r.data_exposed else 'NO'} | "
            f"{r.external_code} | **{r.status}** | {r.notes} |"
        )
    lines += [
        "",
        "## Summary",
        "",
        f"- Total: {report.summary['total']}",
        f"- BLOCK: {report.summary['blocked']}",
        f"- BYPASS: {report.summary['bypass']} "
        f"(known process-trust: {report.summary['known_process_trust_findings']}, "
        f"unknown: {report.summary['unknown_bypasses']})",
        f"- Oracle distinct signatures (excl. control): {report.summary['oracle_distinct_signatures']}",
        f"- Control baseline OK: {report.summary['control_baseline_ok']}",
        f"- Clean (no unknown bypass): {report.summary['clean']}",
        "",
        "## Oracle classes",
        "",
    ]
    for sig, ids in sorted(report.oracle_classes.items(), key=lambda x: -len(x[1])):
        lines.append(f"- `{sig}` → {', '.join(ids)}")
    lines += [
        "",
        "## Interpretation",
        "",
        "- **RT1** documents *in-process* trust: code holding `LocalDataPlane` can seal.",
        "- **RT16** closes the **API/network** boundary: `src/edge_api_server.py` exposes only",
        "  `/health`, `/v1/capabilities`, `/v1/execute` over MVP. Probes for raw",
        "  `issue_for_agent` / `data_plane` return INERT. Deploy untrusted agents as",
        "  separate processes that only speak the Edge API.",
        "- Other attacks must remain **BLOCK** with external code **INERT**.",
        "",
    ]
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ATL Hardened Red-Team v1")
    parser.add_argument("--json", default="testbench/redteam_report.json")
    parser.add_argument("--md", default="testbench/redteam_matrix.md")
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Exit 1 if any unknown bypass exists or baseline fails",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    report = run_redteam()
    md = render_matrix(report)
    print(md)

    out_json = Path(args.json)
    out_md = Path(args.md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "started": report.started,
        "finished": report.finished,
        "summary": report.summary,
        "oracle_classes": report.oracle_classes,
        "results": [asdict(r) for r in report.results],
    }
    out_json.write_text(json.dumps(payload, indent=2))
    out_md.write_text(md)
    print(f"\nWrote {out_json}")
    print(f"Wrote {out_md}")

    if args.require_clean and not report.summary.get("clean"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
