"""
Orquestador interno de lazo cerrado. Une el kernel bitwise, el ajustador de
temperatura, el regulador de exploración y el descubrimiento estructural.

Este módulo es interno (`_internal`); la API pública de una línea vive en
agentguard/__init__.py (`monitor()`). No se garantiza estabilidad de esta
interfaz entre versiones menores.
"""

from __future__ import annotations
import ctypes
import numpy as np
from typing import Dict, Any, Optional, List

from agentguard._internal.mitigation import TemperatureAdjuster
from agentguard._internal.bitstream_profiler import AdaptiveBitstreamFSM
from agentguard._internal.exploration_regulator import QuantumStateRegulator
from agentguard._internal.structural_discovery import discover_structure, StructuralReport


class MonitoringEngine:
    """
    Motor de monitoreo de eventos de agentes. Combina una señal rápida de
    "fricción" bitwise (barata, sub-microsegundo si el kernel C está
    disponible) con un ajustador de logits opcional y un descubridor de
    interacciones no lineales entre señales binarias.

    IMPORTANTE: por defecto opera en modo observación (shadow mode) -- nunca
    bloquea ni modifica nada del agente monitoreado a menos que se pase
    action_mode="enforce" explícitamente, y solo después de validar con
    datos reales que la señal es confiable (ver validation/validate.py).
    """

    def __init__(
        self,
        dimension: int = 8,
        population_size: int = 40,
        target_triplet: tuple = (3.0, 4.0, 5.0),
        seed: int = 42,
        action_mode: str = "shadow",
    ):
        if action_mode not in ("shadow", "enforce"):
            raise ValueError("action_mode debe ser 'shadow' o 'enforce'")
        self.action_mode = action_mode
        self.dimension = dimension
        self.fsm = AdaptiveBitstreamFSM()
        self.temperature_adjuster = TemperatureAdjuster(target_triplet=target_triplet)
        self.regulator = QuantumStateRegulator(
            population_size=population_size, dimension=dimension, seed=seed
        )
        self.telemetry_history: List[np.ndarray] = []
        self.labels_history: List[int] = []

    def evaluate_event(
        self,
        agent_id: str,
        status_mask: int,
        payload_hash: int,
        raw_logs: str,
        logits_vector: Optional[np.ndarray] = None,
        bit_stream: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """Procesa un evento de telemetría de un agente y devuelve señales
        diagnósticas. En modo shadow (default) nunca sugiere acción
        correctiva, solo reporta."""

        friction_popcount = 0
        buffer_noise = 0.0
        if self.fsm._libswar:
            friction_popcount = self.fsm._libswar.evaluate_agent_friction(
                ctypes.c_uint64(status_mask), ctypes.c_uint64(payload_hash)
            )
            buffer_noise = self.fsm._libswar.analyze_swar_buffer(
                raw_logs.encode("utf-8"), len(raw_logs)
            )
        else:
            diff = status_mask ^ payload_hash
            friction_popcount = bin(diff).count("1")
            buffer_noise = len(raw_logs) % 10 / 10.0

        friction_ratio = friction_popcount / 64.0

        fsm_metrics = {}
        if bit_stream is not None:
            fsm_metrics = self.fsm.process_stream(bit_stream)

        temperature_metrics = {}
        if logits_vector is not None:
            _, temperature_metrics = self.temperature_adjuster.process_vector(logits_vector)

        def objective_fn(point: np.ndarray) -> float:
            base_err = np.sum((point - 0.1) ** 2)
            return float(base_err + 2.0 * friction_ratio + 1.5 * buffer_noise)

        tunnel_prob = 0.15 if friction_ratio > 0.4 else 0.05
        regulator_metrics = self.regulator.step(objective_fn, tunnel_prob=tunnel_prob)

        flags = np.array([
            int(friction_ratio > 0.3),
            int(buffer_noise > 0.4),
            int(temperature_metrics.get("homeostasis_active", False)),
            int(regulator_metrics["gate"] == "VETO"),
            int(fsm_metrics.get("pct_escape", 0) > 5.0),
        ], dtype=int)
        self.telemetry_history.append(flags)

        is_flagged = friction_ratio > 0.35 or regulator_metrics["gate"] == "VETO"
        self.labels_history.append(int(is_flagged))

        suggested_action = None
        if self.action_mode == "enforce" and is_flagged:
            suggested_action = "quarantine_for_review"

        return {
            "agent_id": agent_id,
            "signals": {
                "friction_popcount": friction_popcount,
                "friction_ratio": round(friction_ratio, 4),
                "buffer_noise": round(buffer_noise, 4),
                "flagged": bool(is_flagged),
            },
            "fsm": fsm_metrics,
            "temperature_adjustment": temperature_metrics,
            "regulator": regulator_metrics,
            "mode": self.action_mode,
            "suggested_action": suggested_action,
        }

    def run_structural_discovery(self) -> Optional[StructuralReport]:
        if len(self.telemetry_history) < 30:
            return None
        X = np.array(self.telemetry_history)
        y = np.array(self.labels_history)
        if len(np.unique(y)) < 2:
            # Todo el historial marcado o nada marcado: no hay señal que
            # discriminar todavía. No es un error del cliente, es normal en
            # rachas de agentes sanos -- se devuelve None en vez de romper.
            return None
        flag_names = ["HIGH_FRICTION", "LOG_NOISE", "TEMP_ADJUSTED", "VETO_GATE", "ESCAPE_PATTERN"]
        return discover_structure(X, y, flag_names=flag_names, max_degree=4, folds=3)
