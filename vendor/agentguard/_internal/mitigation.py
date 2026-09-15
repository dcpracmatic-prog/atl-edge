"""
Ajustador de temperatura de logits por desviación geométrica de una referencia.

Nota de honestidad técnica: este componente ajusta la temperatura de
muestreo (afila el argmax) cuando una proyección de los top-3 logits se
aleja de un punto de referencia fijo. Es una heurística de intervención,
no un detector validado -- no hay evidencia empírica publicada de que la
"referencia 3-4-5" tenga significado para calidad de salida de un modelo
real. Se documenta como mecanismo de mitigación configurable, y se
recomienda A/B testear su efecto antes de dejarlo activo en producción.
"""

from __future__ import annotations
import numpy as np
from typing import Tuple, Dict, Any, Optional, Union

class TemperatureAdjuster:
    """
    Procesador Homeostático en el hiperboloide H3.
    Mantiene la coherencia del estado proyectando las salidas/logits a un triple (x, y, z)
    y evaluando la desviación del invariante Minkowski P = x² + y² - z²
    respecto a la referencia ideal (terna pitagórica 3, 4, 5 -> P_ref = 0).
    """

    def __init__(
        self,
        target_triplet: Tuple[float, float, float] = (3.0, 4.0, 5.0),
        p_mask: Tuple[float, float, float] = (1.0, 1.0, -1.0),
        sharpen_gain: float = 2.0,
        sharpen_cap: float = 4.0,
        error_threshold: float = 0.05,
        reinforce_top1: float = 0.5,
    ):
        self.target_triplet = target_triplet
        self.p_mask = np.array(p_mask, dtype=np.float64)
        self.sharpen_gain = sharpen_gain
        self.sharpen_cap = sharpen_cap
        self.error_threshold = error_threshold
        self.reinforce_top1 = reinforce_top1

        # Invariante de referencia: 3² + 4² - 5² = 0.0
        ref = np.array(target_triplet, dtype=np.float64)
        self.memory_invariant = float(np.sum((ref ** 2) * self.p_mask))

        # Diagnósticos
        self.last_error = 0.0
        self.last_scale = 1.0
        self.active_flag = False

    def compute_minkowski_invariant(self, triplet: np.ndarray) -> np.ndarray:
        """Calcula P = x² + y² - z² por fila."""
        triplet = np.asarray(triplet, dtype=np.float64)
        return np.sum((triplet ** 2) * self.p_mask, axis=-1)

    def process_vector(self, logits: np.ndarray) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Regula un vector o matriz de logits [B, V] utilizando la métrica H3.
        """
        logits = np.asarray(logits, dtype=np.float64)
        is_1d = (logits.ndim == 1)
        if is_1d:
            logits = np.expand_dims(logits, axis=0)

        batch_size, vocab_size = logits.shape
        k = min(3, vocab_size)
        
        # Extraer top-3 logits normalizados por fila
        top3_indices = np.argsort(logits, axis=-1)[:, -k:]
        top3_values = np.take_along_axis(logits, top3_indices, axis=-1)

        # Pad a 3 si vocab_size < 3
        if k < 3:
            padded = np.zeros((batch_size, 3), dtype=np.float64)
            padded[:, :k] = top3_values
            top3_values = padded

        # Normalización por el máximo valor absoluto
        max_vals = np.maximum(np.max(np.abs(top3_values), axis=-1, keepdims=True), 1e-9)
        triplet = top3_values / max_vals

        p_vals = self.compute_minkowski_invariant(triplet)
        errors = p_vals - self.memory_invariant
        abs_errors = np.abs(errors)

        active = abs_errors > self.error_threshold
        c = 1.0 + self.sharpen_gain * np.minimum(abs_errors, self.sharpen_cap)
        scale = np.where(active, c, 1.0)

        # Aplicar afinamiento por fila
        adjusted_logits = logits * scale[:, np.newaxis]

        # Refuerzo no uniforme en el argmax
        if self.reinforce_top1 > 0:
            argmax_idx = np.argmax(adjusted_logits, axis=-1)
            for i in range(batch_size):
                if active[i]:
                    adjusted_logits[i, argmax_idx[i]] += self.reinforce_top1 * abs_errors[i]

        self.last_error = float(np.mean(errors))
        self.last_scale = float(np.mean(scale))
        self.active_flag = bool(np.any(active))

        result = adjusted_logits[0] if is_1d else adjusted_logits
        metrics = {
            "minkowski_error": self.last_error,
            "sharpen_scale": self.last_scale,
            "homeostasis_active": self.active_flag,
            "p_invariant_mean": float(np.mean(p_vals)),
        }
        return result, metrics
