"""
Hardware jitter signature calibrator.

Measures own latency variability via a portable matmul micro-benchmark.
Produces dimensionless signature [C, B, G, A_adapt] and derived parameters.
No OS telemetry, no privileged APIs.
"""

from __future__ import annotations
import time
import gc
from typing import Dict, Any, List
import numpy as np

MATRIX_SIZE = 120
N_RUNS = 12
WINDOWS_PER_RUN = 25
WARMUP = 3


def micro_benchmark_kernel(size: int = MATRIX_SIZE) -> float:
    t0 = time.perf_counter_ns()
    A = np.random.rand(size, size)
    B = np.random.rand(size, size)
    _ = A @ B
    return (time.perf_counter_ns() - t0) / 1000.0  # µs


def extraer_firma(tau: List[float]) -> np.ndarray:
    tau_arr = np.asarray(tau, dtype=np.float64)
    var_tau = float(np.var(tau_arr))
    C = 1.0 / (1.0 + var_tau)

    mean_tau = float(np.mean(tau_arr))
    median_tau = float(np.median(tau_arr))
    B = float(np.exp(-abs(mean_tau - median_tau) / (median_tau + 1e-9)))

    dtau = np.diff(tau_arr)
    G = 1.0 / (1.0 + (float(np.mean(np.abs(dtau))) if len(dtau) > 0 else 0.0))

    p95 = float(np.percentile(tau_arr, 95))
    p99 = float(np.percentile(tau_arr, 99))
    A_adapt = float(np.exp(-abs(p99 - p95) / (p95 + 1e-6)))

    return np.array([C, B, G, A_adapt], dtype=np.float64)


def calibrar_dsp() -> Dict[str, Any]:
    gc.disable()
    for _ in range(WARMUP):
        micro_benchmark_kernel()

    firmas = []
    for _ in range(N_RUNS):
        ventana = [micro_benchmark_kernel() for _ in range(WINDOWS_PER_RUN)]
        firmas.append(extraer_firma(ventana))
    gc.enable()

    firma = np.mean(firmas, axis=0)
    C, B, G, A = firma
    factor_ruido = float(np.clip(1.0 - A, 0.0, 1.0))

    hist_n = int(round(12 + factor_ruido * 48))
    intervalo_s = int(round(5 + factor_ruido * 15))

    if factor_ruido < 0.25:
        regime = "ESTABLE"
    elif factor_ruido < 0.55:
        regime = "MODERADO"
    else:
        regime = "RUIDOSO"

    return {
        "firma": {
            "C": round(float(C), 4),
            "B": round(float(B), 4),
            "G": round(float(G), 4),
            "A_adapt": round(float(A), 4),
        },
        "factor_ruido": round(factor_ruido, 4),
        "regime": regime,
        "hist_n": hist_n,
        "intervalo_s": intervalo_s,
        "intervalo_ahorro_s": intervalo_s * 3,
        "recommended": {
            "parallelism": "high" if factor_ruido < 0.25 else ("medium" if factor_ruido < 0.55 else "low"),
            "mode": "direct" if factor_ruido < 0.25 else ("normal" if factor_ruido < 0.55 else "conservative"),
        },
    }


if __name__ == "__main__":
    cfg = calibrar_dsp()
    print("Jitter signature:", cfg["firma"])
    print("factor_ruido:", cfg["factor_ruido"], "→", cfg["regime"])
    print("hist_n:", cfg["hist_n"], "| intervalo_s:", cfg["intervalo_s"])
