"""
Regulador de estado con optimización tipo enjambre (erosión hacia el mejor
punto) y saltos de cola pesada (Cauchy) para escapar de mínimos locales.

Nota de honestidad técnica: esto es una técnica establecida de optimización
metaheurística (mutación Cauchy/Lévy flight en vez de Gaussiana) -- válida
y bien documentada en la literatura de optimización, pero no tiene relación
con mecánica cuántica real. Útil como mecanismo de exploración/diversidad
en la búsqueda interna del gate, no como "detección cuántica" de nada.
"""

from __future__ import annotations
import numpy as np
from scipy.stats import cauchy
from typing import Tuple, Dict, Any, Optional, List

class GeometricSpace:
    def __init__(self, points: np.ndarray, bounds: Optional[Tuple[np.ndarray, np.ndarray]] = None):
        self.points = np.asarray(points, dtype=np.float64)
        self.n, self.d = self.points.shape
        self.lower, self.upper = bounds if bounds is not None else (None, None)

    def centroid(self) -> np.ndarray:
        return self.points.mean(axis=0)

    def dispersion(self) -> float:
        c = self.centroid()
        diffs = self.points - c
        return float(np.sqrt(np.mean(np.sum(diffs ** 2, axis=1))))

    def clip_to_bounds(self):
        if self.lower is not None and self.upper is not None:
            self.points = np.clip(self.points, self.lower, self.upper)


def _fitness_to_weights(fitness: np.ndarray, beta: float = 4.0) -> np.ndarray:
    f = np.asarray(fitness, dtype=np.float64)
    f_norm = (f - f.min()) / (np.ptp(f) + 1e-12)
    w = np.exp(-beta * f_norm)
    return w / w.sum()


def erosion(space: GeometricSpace, fitness: np.ndarray, strength: float = 0.3) -> GeometricSpace:
    best_idx = np.argmin(fitness)
    best_point = space.points[best_idx]
    weights = _fitness_to_weights(fitness)
    weighted_center = np.average(space.points, axis=0, weights=weights)
    target = 0.5 * best_point + 0.5 * weighted_center
    new_points = space.points + strength * (target - space.points)
    new_space = GeometricSpace(new_points, (space.lower, space.upper) if space.lower is not None else None)
    new_space.clip_to_bounds()
    return new_space


def quantum_tunneling(
    space: GeometricSpace, strength: float = 0.3, tunnel_prob: float = 0.05, rng: Optional[np.random.Generator] = None, min_scale: float = 1e-3
) -> GeometricSpace:
    """
    Operador de tunelamiento cuántico-inspirado con distribución de Cauchy (cola pesada).
    Aplica saltos no locales para escapar de pozos o trampas de atención/mínimos locales.
    """
    rng = rng or np.random.default_rng()
    scale = max(strength * space.dispersion(), min_scale)

    n, d = space.points.shape
    tunnel_mask = rng.random(n) < tunnel_prob

    new_points = space.points.copy()

    # Movimiento gaussiano regular
    classical_noise = rng.normal(0.0, scale, size=(n, d))
    new_points[~tunnel_mask] += classical_noise[~tunnel_mask]

    # Salto de Cauchy no local
    n_tunnel = int(tunnel_mask.sum())
    if n_tunnel > 0:
        tunnel_noise = cauchy.rvs(loc=0.0, scale=scale, size=(n_tunnel, d), random_state=rng)
        new_points[tunnel_mask] += tunnel_noise

    new_space = GeometricSpace(new_points, (space.lower, space.upper) if space.lower is not None else None)
    new_space.clip_to_bounds()
    return new_space


class QuantumStateRegulator:
    """
    Regulador de estado homeostático con histéresis y tunelamiento cuántico-inspirado.
    """

    def __init__(
        self,
        population_size: int = 40,
        dimension: int = 8,
        enter_ratio: float = 0.30,
        exit_ratio: float = 0.20,
        exit_persist: int = 4,
        seed: Optional[int] = 42,
    ):
        self.pop_size = population_size
        self.dim = dimension
        self.enter_ratio = enter_ratio
        self.exit_ratio = exit_ratio
        self.exit_persist = exit_persist
        self.rng = np.random.default_rng(seed)

        self.space = GeometricSpace(
            self.rng.uniform(-1.0, 1.0, size=(population_size, dimension)),
            bounds=(np.full(dimension, -2.0), np.full(dimension, 2.0))
        )
        self.max_recent_dispersion = self.space.dispersion()
        self.hysteresis_count = 0
        self.in_veto_state = False

    def step(self, objective_fn, tunnel_prob: float = 0.05) -> Dict[str, Any]:
        """Ejecuta un paso de evolución geométrica con tunelamiento."""
        # 1. Aplicar tunelamiento cuántico
        self.space = quantum_tunneling(self.space, strength=0.3, tunnel_prob=tunnel_prob, rng=self.rng)

        # 2. Evaluar fitness y aplicar erosión
        fitness = np.array([objective_fn(p) for p in self.space.points])
        self.space = erosion(self.space, fitness, strength=0.3)

        curr_dispersion = self.space.dispersion()
        if curr_dispersion > self.max_recent_dispersion:
            self.max_recent_dispersion = curr_dispersion

        # 3. Lógica de histéresis del State Regulator
        health_ratio = curr_dispersion / (self.max_recent_dispersion + 1e-9)

        if not self.in_veto_state:
            if health_ratio < self.enter_ratio:
                self.in_veto_state = True
                self.hysteresis_count = 0
        else:
            if health_ratio >= (1.0 - self.exit_ratio):
                self.hysteresis_count += 1
                if self.hysteresis_count >= self.exit_persist:
                    self.in_veto_state = False
                    self.hysteresis_count = 0
            else:
                self.hysteresis_count = 0

        gate_status = "VETO" if self.in_veto_state else "ALLOW"
        suggestion = (
            "protected: consolidate and request context before expanding"
            if self.in_veto_state
            else "nominal: optimal exploration mode"
        )

        best_idx = np.argmin(fitness)
        return {
            "health": round(health_ratio, 4),
            "gate": gate_status,
            "suggestion": suggestion,
            "dispersion": curr_dispersion,
            "best_fitness": float(fitness[best_idx]),
            "best_point": self.space.points[best_idx].copy(),
        }
