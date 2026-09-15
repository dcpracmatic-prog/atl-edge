#!/usr/bin/env python3
"""
Integraciones: AgentGuard + EO telemetry schema + SmartToken real + closed loop slim.
"""

from __future__ import annotations

import hashlib
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_PKG = Path(__file__).resolve().parents[1]
_VENDOR = _PKG / "vendor"
_EO = _PKG / "eo_probe"
for p in (str(_VENDOR), str(_EO), str(_PKG)):
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------- SmartToken (LWE / structural — governance & observation) ----------
try:
    from smart_token.token import SmartTokenV1
    from smart_token.structural import governance_fingerprint
    from smart_token.lwe import lwe_keygen, lwe_commit, lwe_open
    SMART_TOKEN_OK = True
except Exception as e:
    SMART_TOKEN_OK = False
    _ST_ERR = str(e)

# ---------- SmartTokenProd (ML-KEM + friction — long-lived file protection) ----------
try:
    from src.long_lived_protection import (
        is_available as long_lived_available,
        status as long_lived_status,
        protect_artifact,
        open_artifact,
        artifact_friction_status,
        SMART_TOKEN_PROD_OK,
        STP_VERSION,
    )
except Exception as e:
    SMART_TOKEN_PROD_OK = False
    STP_VERSION = "unavailable"
    long_lived_available = lambda: False  # type: ignore
    long_lived_status = lambda: {"smart_token_prod_available": False, "import_error": str(e)}  # type: ignore
    protect_artifact = open_artifact = artifact_friction_status = None  # type: ignore

# ---------- Telemetry schema EO ----------
try:
    from src.telemetry_schema import TelemetryEvent as EOTelemetryEvent  # type: ignore
    SCHEMA_OK = True
except Exception:
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "eo_telemetry_schema", _EO / "src" / "telemetry_schema.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        EOTelemetryEvent = mod.TelemetryEvent
        SCHEMA_OK = True
    except Exception as e:
        SCHEMA_OK = False
        _SCHEMA_ERR = str(e)
        EOTelemetryEvent = None  # type: ignore

# ---------- AgentGuard (real if sklearn present; else shadow stub on SWAR) ----------
AGENTGUARD_OK = False
_ag_monitor = None
try:
    from agentguard import monitor as _ag_monitor, MonitorResult as AGMonitorResult
    AGENTGUARD_OK = True
except Exception:
    AGMonitorResult = None  # type: ignore


@dataclass
class GuardResult:
    flagged: bool
    reason: str
    friction_ratio: float
    mode: str
    source: str  # agentguard | swar_stub


def agentguard_monitor(
    agent_id: str,
    log_text: str = "",
    status_code: str = "OK",
    tool_name: Optional[str] = None,
    status_mask: Optional[int] = None,
    payload_hash: Optional[int] = None,
) -> GuardResult:
    """Shadow monitor: real AgentGuard if deps OK, else SWAR friction stub."""
    if AGENTGUARD_OK and _ag_monitor is not None:
        r = _ag_monitor(
            agent_id=agent_id,
            log_text=log_text or status_code,
            status_code=status_code,
            tool_name=tool_name,
        )
        return GuardResult(
            flagged=bool(r.flagged),
            reason=str(r.reason or ""),
            friction_ratio=float(getattr(r, "friction_ratio", 0.0) or 0.0),
            mode=str(getattr(r, "mode", "shadow")),
            source="agentguard",
        )

    # Stub: same mask/hash idea as agentguard public API + SWAR if available
    from src.atl_core import load_swar
    eng, _ = load_swar()
    if status_mask is None:
        key = f"{status_code}|{tool_name or ''}".encode()
        status_mask = int.from_bytes(hashlib.sha256(key).digest()[:8], "big")
    if payload_hash is None:
        payload_hash = int.from_bytes(
            hashlib.sha256((log_text or "").encode()).digest()[:8], "big"
        )
    friction = 0.0
    if eng is not None:
        friction = float(eng.evaluate_friction(status_mask, payload_hash))
    flagged = friction >= 0.42 or status_code.upper() in ("ERROR", "FAIL", "TIMEOUT")
    return GuardResult(
        flagged=flagged,
        reason=("high_swar_friction" if friction >= 0.42 else "")
        or ("status_" + status_code if flagged else "ok"),
        friction_ratio=friction,
        mode="shadow",
        source="swar_stub",
    )


# ---------- Closed loop slim (schema + SWAR + AOM + agentguard flag) ----------

@dataclass
class ClosedLoopResult:
    event_id: str
    friction: float
    regime: str
    smoothed: float
    guard: GuardResult
    field_recommended: bool
    detail: str


class ClosedLoopSlim:
    """
    Subconjunto del ClosedLoopOrchestrator de EO:
      TelemetryEvent → SWAR friction → AOM membrane → AgentGuard shadow
    Sin LLM controller / métricas Prometheus (eso es ops, no núcleo MVP).
    """

    def __init__(self, hist_n: int = 16, min_phi_gate: float = 0.35):
        from src.atl_core import load_swar
        self.engine, Membrane = load_swar()
        self.membrane = Membrane(capacity=hist_n) if Membrane and self.engine else None
        self.min_phi_gate = min_phi_gate

    def process(
        self,
        *,
        agent_id: str,
        task_name: str,
        status_mask: int = 0,
        payload: bytes = b"",
        latency_ms: float = 0.0,
        error_count: int = 0,
        log_text: str = "",
        phi: float = 0.0,
    ) -> ClosedLoopResult:
        payload_hash = int.from_bytes(hashlib.sha256(payload or b"\x00").digest()[:8], "big")
        event_id = str(uuid.uuid4())

        friction = 0.0
        regime = "ESTABLE"
        smoothed = 0.0
        if self.engine and self.membrane is not None:
            friction = float(self.engine.evaluate_friction(status_mask, payload_hash))
            regime, smoothed = self.membrane.push(friction)
            smoothed = float(smoothed)
        else:
            smoothed = min(1.0, latency_ms / 500.0)

        status_code = "ERROR" if error_count else "OK"
        guard = agentguard_monitor(
            agent_id=agent_id,
            log_text=log_text or task_name,
            status_code=status_code,
            status_mask=status_mask,
            payload_hash=payload_hash,
        )

        field_ok = (
            regime == "ESTABLE"
            and not guard.flagged
            and phi >= self.min_phi_gate
            and error_count == 0
        )
        detail = f"regime={regime} friction={smoothed:.3f} guard={guard.source}:{guard.flagged}"
        return ClosedLoopResult(
            event_id=event_id,
            friction=smoothed,
            regime=regime,
            smoothed=smoothed,
            guard=guard,
            field_recommended=field_ok,
            detail=detail,
        )


# ---------- Smart token helper for ATL seals ----------

def make_governance_token(outcomes: Optional[List[int]] = None, secret_bits: Optional[List[int]] = None, seed: int = 42):
    """SmartTokenV1 real if available; else None."""
    if not SMART_TOKEN_OK:
        return None
    if outcomes is None:
        outcomes = [0, 1, 1, 0, 1, 0, 0, 1]
    if secret_bits is None:
        secret_bits = [1, 0, 1, 1, 0, 0, 1, 0]
    return SmartTokenV1(outcomes, secret_bits, seed=seed)


def integration_status() -> Dict[str, Any]:
    return {
        "agentguard": AGENTGUARD_OK,
        "smart_token": SMART_TOKEN_OK,
        "telemetry_schema": SCHEMA_OK,
        "agentguard_note": None if AGENTGUARD_OK else "using SWAR stub (install scikit-learn for full agentguard)",
        "smart_token_note": None if SMART_TOKEN_OK else locals().get("_ST_ERR"),
    }
