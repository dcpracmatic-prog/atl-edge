"""
agentguard — monitoreo de anomalías de comportamiento para agentes de IA.

Uso mínimo (modo shadow, por defecto, no bloquea nada):

    import agentguard

    result = agentguard.monitor(
        agent_id="agent_7",
        log_text="ERROR tool call timed out",
    )
    if result.flagged:
        print("evento marcado:", result.reason)

Todo corre en el proceso del cliente. No hay servidor, no hay red saliente,
no hay dependencia de backend. Los eventos se acumulan en memoria y,
opcionalmente, en un archivo JSONL local (`log_path`) para análisis con
`agentguard.discover_patterns()` o el harness de validación en `validation/`.

Instalación sin fricción: funciona en Python puro sin compilador. El kernel
C opcional se auto-compila en segundo plano si hay gcc/clang/cl disponible;
si no, usa fallback Python automáticamente y en silencio. Para desactivar
el intento de compilación: variable de entorno AGENTGUARD_DISABLE_C_KERNEL=1.
"""

from __future__ import annotations
import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

import numpy as np

from agentguard._internal.engine import MonitoringEngine

__version__ = "0.1.0"
__all__ = ["monitor", "MonitorResult", "AgentGuard", "discover_patterns"]


@dataclass
class MonitorResult:
    agent_id: str
    flagged: bool
    friction_ratio: float
    buffer_noise: float
    gate: str
    mode: str
    suggested_action: Optional[str]
    reason: str
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)


def _status_to_mask(status_code: str, tool_name: Optional[str]) -> int:
    key = f"{status_code}|{tool_name or ''}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(key).digest()[:8], "big")


def _log_to_hash(log_text: str) -> int:
    return int.from_bytes(hashlib.sha256(log_text.encode("utf-8")).digest()[:8], "big")


class AgentGuard:
    """
    Instancia con estado, para cuando necesitas acumular eventos y correr
    `discover_patterns()` sobre un historial (mínimo 30 eventos).

    Para el caso simple de "evalúa este evento y ya", usa la función de
    módulo `agentguard.monitor(...)`, que gestiona una instancia global.
    """

    def __init__(
        self,
        action_mode: str = "shadow",
        log_path: Optional[str] = None,
        seed: int = 42,
    ):
        self._engine = MonitoringEngine(action_mode=action_mode, seed=seed)
        self.log_path = log_path
        self._lock = threading.Lock()

    def monitor(
        self,
        agent_id: str,
        log_text: str,
        status_code: str = "OK",
        tool_name: Optional[str] = None,
        logits: Optional[List[float]] = None,
    ) -> MonitorResult:
        status_mask = _status_to_mask(status_code, tool_name)
        payload_hash = _log_to_hash(log_text)
        logits_vector = np.asarray(logits, dtype=np.float64) if logits is not None else None

        with self._lock:
            res = self._engine.evaluate_event(
                agent_id=agent_id,
                status_mask=status_mask,
                payload_hash=payload_hash,
                raw_logs=log_text,
                logits_vector=logits_vector,
            )

        result = MonitorResult(
            agent_id=agent_id,
            flagged=res["signals"]["flagged"],
            friction_ratio=res["signals"]["friction_ratio"],
            buffer_noise=res["signals"]["buffer_noise"],
            gate=res["regulator"]["gate"],
            mode=res["mode"],
            suggested_action=res["suggested_action"],
            reason=(
                f"friction_ratio={res['signals']['friction_ratio']:.3f}, "
                f"gate={res['regulator']['gate']}"
            ),
            raw=res,
        )

        if self.log_path:
            self._append_log(status_code, tool_name, result)

        return result

    def _append_log(self, status_code: str, tool_name: Optional[str], result: MonitorResult) -> None:
        row = {
            "agent_id": result.agent_id,
            "status_code": status_code,
            "tool_name": tool_name,
            "flagged": result.flagged,
            "friction_ratio": result.friction_ratio,
            "gate": result.gate,
            "mode": result.mode,
        }
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)) or ".", exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def discover_patterns(self):
        """Ejecuta el descubridor de interacciones no lineales sobre el
        historial acumulado en esta instancia. Requiere >=30 eventos.
        Devuelve None si no hay suficientes."""
        return self._engine.run_structural_discovery()


_default_instance: Optional[AgentGuard] = None
_default_lock = threading.Lock()


def _get_default() -> AgentGuard:
    global _default_instance
    with _default_lock:
        if _default_instance is None:
            _default_instance = AgentGuard(action_mode="shadow")
        return _default_instance


def monitor(
    agent_id: str,
    log_text: str,
    status_code: str = "OK",
    tool_name: Optional[str] = None,
    logits: Optional[List[float]] = None,
) -> MonitorResult:
    """
    Punto de entrada de una línea. Usa una instancia global en modo shadow
    (observación, nunca bloquea). Para acumular historial propio, control de
    modo enforce, o logging a archivo, usa `AgentGuard(...)` directamente.
    """
    return _get_default().monitor(
        agent_id=agent_id,
        log_text=log_text,
        status_code=status_code,
        tool_name=tool_name,
        logits=logits,
    )


def discover_patterns():
    """Descubre patrones sobre el historial acumulado por la instancia
    global usada por `monitor()`. Requiere >=30 llamadas previas a monitor()."""
    return _get_default().discover_patterns()
