"""
Bare-metal C bridge + Adaptive Observability Membrane (Schmitt hysteresis).
"""

from __future__ import annotations
import ctypes
import os
from typing import Tuple
from pathlib import Path


def _find_lib() -> str:
    candidates = [
        Path(__file__).resolve().parent.parent / "core" / "libswar_fleet.so",
        Path(__file__).resolve().parent.parent / "core" / "libswar_fleet.dylib",
        Path.cwd() / "core" / "libswar_fleet.so",
        Path.cwd() / "libswar_fleet.so",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    raise FileNotFoundError(
        "C library not found. Run `make build` first. "
        f"Looked in: {[str(c) for c in candidates]}"
    )


class BareMetalEngine:
    def __init__(self, lib_path: str | None = None):
        path = lib_path or _find_lib()
        self.c_engine = ctypes.CDLL(path)
        self.c_engine.evaluate_agent_friction.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
        self.c_engine.evaluate_agent_friction.restype = ctypes.c_uint64
        self.c_engine.analyze_swar_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        self.c_engine.analyze_swar_buffer.restype = ctypes.c_double

    def evaluate_friction(self, status_mask: int, payload_hash: int) -> float:
        raw = self.c_engine.evaluate_agent_friction(
            status_mask & 0xFFFFFFFFFFFFFFFF,
            payload_hash & 0xFFFFFFFFFFFFFFFF,
        )
        return float(raw) / 32.0

    def evaluate_text_noise(self, text: str) -> float:
        buf = text.encode("utf-8")
        return float(self.c_engine.analyze_swar_buffer(buf, len(buf)))


class DynamicAOMMembrane:
    """
    Schmitt-trigger membrane with dead-band hysteresis.
    Prevents chatter under hardware jitter.
    """

    def __init__(self, capacity: int = 12):
        self.capacity = max(8, min(int(capacity), 64))
        self.history: list[float] = []
        self.state = "ESTABLE"

    def push(self, score: float) -> Tuple[str, float]:
        self.history.append(float(score))
        if len(self.history) > self.capacity:
            self.history.pop(0)

        smoothed = sum(self.history) / len(self.history)

        if self.state == "ESTABLE":
            if smoothed >= 0.42:
                self.state = "INESTABLE"
        elif self.state == "INESTABLE":
            if smoothed >= 0.68:
                self.state = "CONFLICTO"
            elif smoothed < 0.35:
                self.state = "ESTABLE"
        elif self.state == "CONFLICTO":
            if smoothed < 0.58:
                self.state = "INESTABLE"

        return self.state, smoothed
