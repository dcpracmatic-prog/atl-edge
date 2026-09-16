#!/usr/bin/env python3
"""
ATL Edge Package — núcleo integrado
===================================
FIELD + DSP + DCP + SmartToken + ObservationStack (OTEL/local + SWAR fallback)

Observation modes:
  primary  — only free telemetry provider
  auto     — primary on; SWAR only if primary blocked/silent (default)
  hardened — SWAR always on (vulnerability case)
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Hashable, List, Optional, Sequence

import numpy as np

# ---------------------------------------------------------------------------
# Resolve Edge Observer SWAR path (bundled under package/eo_probe)
# ---------------------------------------------------------------------------

_PKG = Path(__file__).resolve().parents[1]
_EO = _PKG / "eo_probe"
_LIB = _EO / "core" / "libswar_fleet.so"


def load_swar():
    """Load SWAR without colliding with package src/ on sys.path."""
    try:
        import ctypes
        import importlib.util
        po = _EO / "src" / "primitive_observer.py"
        spec = importlib.util.spec_from_file_location("eo_primitive_observer", po)
        if spec is None or spec.loader is None:
            return None, None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        Membrane = mod.DynamicAOMMembrane

        class _Engine:
            def __init__(self, path: str):
                self.c = ctypes.CDLL(path)
                self.c.evaluate_agent_friction.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
                self.c.evaluate_agent_friction.restype = ctypes.c_uint64

            def evaluate_friction(self, status_mask: int, payload_hash: int) -> float:
                raw = self.c.evaluate_agent_friction(
                    status_mask & 0xFFFFFFFFFFFFFFFF,
                    payload_hash & 0xFFFFFFFFFFFFFFFF,
                )
                return float(raw) / 32.0

        if not _LIB.exists():
            return None, Membrane
        return _Engine(str(_LIB)), Membrane
    except Exception:
        return None, None


# ============================ FIELD ============================

@dataclass
class FieldMemory:
    threshold: int = 2
    counts: Counter = field(default_factory=Counter)
    n_observations: int = 0

    def strong_edges(self) -> set:
        return {e for e, n in self.counts.items() if n >= self.threshold}

    def observe(self, path: Sequence[Hashable]) -> None:
        self.n_observations += 1
        for a, b in zip(path, path[1:]):
            self.counts[(a, b)] += 1

    def work(self, path: Sequence[Hashable]) -> tuple[int, int]:
        strong = self.strong_edges()
        edges = list(zip(path, path[1:]))
        reuse = sum(1 for e in edges if e in strong)
        return max(1, len(path) - reuse) if path else 1, reuse

    def overlap_ratio(self, path: Sequence[Hashable]) -> float:
        edges = list(zip(path, path[1:]))
        if not edges:
            return 0.0
        strong = self.strong_edges()
        return sum(1 for e in edges if e in strong) / len(edges)


# ============================ DSP ============================

def _micro(size: int = 64) -> float:
    t0 = time.perf_counter_ns()
    _ = np.random.rand(size, size) @ np.random.rand(size, size)
    return (time.perf_counter_ns() - t0) / 1000.0


def calibrate_dsp(n_runs: int = 5, windows: int = 12) -> Dict[str, Any]:
    for _ in range(2):
        _micro()
    firmas = []
    for _ in range(n_runs):
        tau = np.array([_micro() for _ in range(windows)], dtype=np.float64)
        C = 1.0 / (1.0 + float(np.var(tau)))
        mean, med = float(tau.mean()), float(np.median(tau))
        B = float(np.exp(-abs(mean - med) / (med + 1e-9)))
        d = np.diff(tau)
        G = 1.0 / (1.0 + (float(np.mean(np.abs(d))) if len(d) else 0.0))
        p95, p99 = float(np.percentile(tau, 95)), float(np.percentile(tau, 99))
        A = float(np.exp(-abs(p99 - p95) / (p95 + 1e-6)))
        firmas.append([C, B, G, A])
    C, B, G, A = np.mean(firmas, axis=0)
    factor = float(np.clip(1.0 - A, 0.0, 1.0))
    hist_n = int(round(12 + factor * 48))
    intervalo = int(round(5 + factor * 15))
    regime = "ESTABLE" if factor < 0.25 else ("MODERADO" if factor < 0.55 else "RUIDOSO")
    return {
        "C": float(C), "B": float(B), "G": float(G), "A_adapt": float(A),
        "factor_ruido": factor, "hist_n": hist_n, "intervalo_s": intervalo,
        "intervalo_ahorro_s": intervalo * 3, "regime": regime,
    }


# ============================ DCP + SmartToken ============================

class DCPEngine:
    def __init__(self, master_seed: bytes):
        if len(master_seed) != 32:
            raise ValueError("master_seed must be 32 bytes")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.aesgcm = AESGCM(bytes(master_seed))

    def seal(self, plaintext: bytes, hardware_id: str, ttl: int, extra_aad: bytes = b""):
        nonce = os.urandom(12)
        exp = time.time() + int(ttl)
        aad = f"{hardware_id}|{exp:.17g}|".encode() + extra_aad
        return nonce + self.aesgcm.encrypt(nonce, plaintext, aad), exp

    def open(self, package: bytes, hardware_id: str, exp: float, extra_aad: bytes = b""):
        if time.time() > exp:
            raise ValueError("APOPTOSIS: TTL expired")
        nonce, ct = package[:12], package[12:]
        aad = f"{hardware_id}|{float(exp):.17g}|".encode() + extra_aad
        try:
            return self.aesgcm.decrypt(nonce, ct, aad)
        except Exception as e:
            raise ValueError("Hardware/token mismatch or corrupt") from e


class SmartToken:
    @staticmethod
    def fingerprint(path: Sequence[Hashable], payload: bytes = b"") -> bytes:
        h = hashlib.sha256()
        for s in path:
            h.update(str(s).encode())
            h.update(b"|")
        h.update(b"::")
        h.update(payload)
        return h.digest()

    @staticmethod
    def short_id(fp: bytes) -> str:
        return fp[:8].hex()


# ============================ Telemetry (free provider) ============================

@dataclass
class TelemetryEvent:
    event_id: str
    agent_id: str
    task_name: str
    status_mask: int
    payload_hash: int
    latency_ms: float
    error_count: int
    ts: float


class FreeTelemetryProvider:
    """OpenTelemetry if available; else local structured buffer (always free)."""

    def __init__(self, service_name: str = "atl"):
        self._events: Deque[TelemetryEvent] = deque(maxlen=2048)
        self._last = time.time()
        self._otel = False
        self._counter = None
        self._hist = None
        try:
            from opentelemetry import metrics
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.resources import Resource
            metrics.set_meter_provider(MeterProvider(resource=Resource.create({"service.name": service_name})))
            m = metrics.get_meter("atl")
            self._counter = m.create_counter("atl_events_total")
            self._hist = m.create_histogram("atl_latency_ms")
            self._otel = True
        except Exception:
            pass

    @property
    def backend(self) -> str:
        return "opentelemetry" if self._otel else "local_structured"

    def emit(self, ev: TelemetryEvent) -> None:
        self._events.append(ev)
        self._last = time.time()
        if self._otel and self._counter is not None:
            a = {"agent_id": ev.agent_id, "task": ev.task_name}
            self._counter.add(1, a)
            if self._hist:
                self._hist.record(ev.latency_ms, a)

    def age_s(self) -> float:
        return time.time() - self._last


# ============================ Observation stack ============================

@dataclass
class ObsResult:
    fallback_used: bool
    friction: float
    regime: str
    signal_intact: bool
    detail: str
    primary_backend: str


class ObservationStack:
    def __init__(
        self,
        mode: str = "auto",
        agent_id: str = "agent-1",
        silence_seconds: float = 15.0,
        dsp: Optional[Dict[str, Any]] = None,
    ):
        assert mode in ("primary", "auto", "hardened")
        self.mode = mode
        self.agent_id = agent_id
        self.silence_seconds = silence_seconds
        self.dsp = dsp or calibrate_dsp()
        self.primary = FreeTelemetryProvider(f"atl-{agent_id}")
        self.engine, Membrane = load_swar()
        self.swar_ok = self.engine is not None
        self.membrane = Membrane(capacity=self.dsp["hist_n"]) if self.swar_ok and Membrane else None
        self._fallback_on = mode == "hardened" and self.swar_ok
        self._fb_reason = "hardened_mode" if self._fallback_on else ""

    def _activate_fb(self, reason: str) -> None:
        if self.swar_ok:
            self._fallback_on = True
            self._fb_reason = reason

    def _deactivate_fb(self) -> None:
        if self.mode != "hardened":
            self._fallback_on = False
            self._fb_reason = ""

    def process(
        self,
        task_name: str,
        *,
        payload: bytes = b"",
        status_mask: int = 0,
        latency_ms: float = 0.0,
        error_count: int = 0,
        primary_blocked: bool = False,
    ) -> ObsResult:
        ph = int(hashlib.sha256(payload or b"\x00").hexdigest()[:16], 16)
        ev = TelemetryEvent(
            event_id=str(uuid.uuid4()),
            agent_id=self.agent_id,
            task_name=task_name,
            status_mask=int(status_mask) & 0xFFFFFFFFFFFFFFFF,
            payload_hash=ph,
            latency_ms=float(latency_ms),
            error_count=int(error_count),
            ts=time.time(),
        )

        fail = None
        if primary_blocked:
            fail = "primary_channel_blocked"
        else:
            self.primary.emit(ev)

        use_fb = False
        if self.mode == "hardened":
            use_fb = self.swar_ok
            self._activate_fb("hardened_mode")
        elif self.mode == "auto" and fail:
            use_fb = self.swar_ok
            self._activate_fb(fail)
        elif self.mode == "auto" and not fail and self._fallback_on:
            self._deactivate_fb()

        if use_fb and self.swar_ok and self.membrane is not None:
            friction = float(self.engine.evaluate_friction(ev.status_mask, ev.payload_hash))
            regime, smoothed = self.membrane.push(friction)
            friction = float(smoothed)
            detail = f"fallback_swar:{self._fb_reason} friction={friction:.4f}"
            intact = fail is None
        else:
            friction = min(1.0, 0.5 * min(1.0, latency_ms / 500.0) + 0.5 * min(1.0, error_count / 5.0))
            regime = "ESTABLE" if friction < 0.35 else ("INESTABLE" if friction < 0.68 else "CONFLICTO")
            detail = f"primary:{self.primary.backend}"
            intact = fail is None
            use_fb = False

        if primary_blocked:
            intact = False
            detail = f"PRIMARY_BLOCKED → {detail}"

        return ObsResult(use_fb, friction, regime, intact, detail, self.primary.backend)


# ============================ ATL control plane ============================

@dataclass
class ATLDecision:
    use_field: bool
    phi: float
    work_field: int
    work_base: int
    regime: str
    friction: float
    seal_ttl: int
    token_id: str
    fallback_used: bool
    signal_intact: bool
    reason: str


class AdaptiveTrustLoop:
    def __init__(
        self,
        field: FieldMemory,
        obs: ObservationStack,
        dcp: DCPEngine,
        hardware_id: str,
        min_phi: float = 0.35,
    ):
        self.field = field
        self.obs = obs
        self.dcp = dcp
        self.hardware_id = hardware_id
        self.min_phi = min_phi
        self.dsp = obs.dsp

    def decide(
        self,
        path: Sequence[Hashable],
        *,
        latency_ms: float = 0.0,
        error: bool = False,
        payload: bytes = b"",
        status_mask: int = 0,
        primary_blocked: bool = False,
    ) -> ATLDecision:
        phi = self.field.overlap_ratio(path)
        wf, _ = self.field.work(path)
        wb = max(1, len(path))
        o = self.obs.process(
            "→".join(map(str, path)),
            payload=payload,
            status_mask=status_mask,
            latency_ms=latency_ms,
            error_count=1 if error else 0,
            primary_blocked=primary_blocked,
        )
        fp = SmartToken.fingerprint(path, payload)
        tid = SmartToken.short_id(fp)

        # TTL by regime / integrity
        if not o.signal_intact or error or o.regime == "CONFLICTO":
            ttl = max(30, self.dsp["intervalo_s"] * 2)
        elif o.regime == "INESTABLE" or self.dsp["regime"] == "RUIDOSO":
            ttl = self.dsp["intervalo_s"] * 6
        else:
            ttl = self.dsp["intervalo_s"] * 12

        use = (
            o.signal_intact
            and not error
            and o.regime == "ESTABLE"
            and phi >= self.min_phi
            and not o.fallback_used  # under attack/fallback: don't trust structural optim
        )
        if not o.signal_intact:
            reason = f"señales comprometidas ({o.detail}) → FIELD off"
        elif error:
            reason = "error_runtime → FIELD off"
        elif o.fallback_used:
            reason = f"fallback SWAR activo ({o.detail}) → FIELD off (modo defensivo)"
        elif o.regime != "ESTABLE":
            reason = f"régimen {o.regime} friction={o.friction:.2f} → FIELD off"
        elif phi < self.min_phi:
            reason = f"phi={phi:.2f} < {self.min_phi} → FIELD off"
        else:
            reason = f"ESTABLE + phi={phi:.2f} + primario OK → FIELD on"

        return ATLDecision(
            use_field=use, phi=phi, work_field=wf, work_base=wb,
            regime=o.regime, friction=o.friction, seal_ttl=ttl,
            token_id=tid, fallback_used=o.fallback_used,
            signal_intact=o.signal_intact, reason=reason,
        )

    def commit(self, path: Sequence[Hashable]) -> None:
        self.field.observe(path)

    def seal(self, path: Sequence[Hashable], data: bytes, ttl: int, meta: bytes = b""):
        fp = SmartToken.fingerprint(path, meta)
        sealed, exp = self.dcp.seal(data, self.hardware_id, ttl, extra_aad=fp)
        return sealed, exp, SmartToken.short_id(fp)

    def open(self, path: Sequence[Hashable], package: bytes, exp: float, meta: bytes = b""):
        fp = SmartToken.fingerprint(path, meta)
        return self.dcp.open(package, self.hardware_id, exp, extra_aad=fp)


# ============================ Self-test ============================

def run_selftest() -> bool:
    print("=" * 72)
    print("ATL EDGE PACKAGE — selftest integrado")
    print("=" * 72)

    eng, _ = load_swar()
    print(f"SWAR: {'OK' if eng else 'MISSING'}")
    if eng:
        print(f"  friction sample={eng.evaluate_friction(0xF0, 0x0F):.4f}")

    dsp = calibrate_dsp()
    print(f"DSP:  A={dsp['A_adapt']:.3f} hist_n={dsp['hist_n']} regime={dsp['regime']}")

    field = FieldMemory(threshold=2)
    for _ in range(3):
        field.observe(("lookup", "normalize", "validate"))
        field.observe(("lookup", "validate"))
        field.observe(("lookup", "normalize", "validate", "publish"))

    dcp = DCPEngine(b"9" * 32)
    obs = ObservationStack(mode="auto", agent_id="t1", dsp=dsp)
    atl = AdaptiveTrustLoop(field, obs, dcp, hardware_id="node-1")

    path = ("lookup", "normalize", "validate", "publish")
    d1 = atl.decide(path, latency_ms=20, payload=b"ok")
    print(f"\n[healthy] field={d1.use_field} fb={d1.fallback_used} regime={d1.regime}")
    print(f"  {d1.reason}")

    sealed, exp, tid = atl.seal(path, b"secret", d1.seal_ttl, b"ok")
    opened = atl.open(path, sealed, exp, b"ok")
    print(f"  seal/open={opened==b'secret'} token={tid}")

    d2 = atl.decide(path, latency_ms=20, payload=b"x", primary_blocked=True)
    print(f"\n[blocked] field={d2.use_field} fb={d2.fallback_used} intact={d2.signal_intact}")
    print(f"  {d2.reason}")

    d3 = atl.decide(path, latency_ms=800, error=True)
    print(f"\n[error]   field={d3.use_field}  {d3.reason}")

    # FIELD props
    m = FieldMemory(threshold=2)
    for _ in range(20):
        m.observe(("a", "b", "c"))
    w, r = m.work(("a", "b", "c"))
    prop1 = w < 3

    ok = bool(eng) and d1.use_field and opened == b"secret" and (not d2.use_field) and d2.fallback_used and (not d3.use_field) and prop1
    print("\n" + "=" * 72)
    print(f"RESULTADO: {'PASS' if ok else 'FAIL'}")
    print("=" * 72)
    return ok


if __name__ == "__main__":
    run_selftest()
