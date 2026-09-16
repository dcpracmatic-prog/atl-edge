"""
Núcleo de dureza — LWE (Learning With Errors) educativo, tipo Regev simplificado.

ADVERTENCIA — LÉASE ANTES DE USAR:
Esta implementación es para fines de arquitectura/demostración. Los parámetros
(n=64, q=3329, sigma=2.0) NO han sido revisados criptográficamente ni analizados
para dureza real. NO ES APTA PARA PRODUCCIÓN.

Para un despliegue real, sustituir este módulo por una librería auditada de
un esquema estandarizado NIST PQC (ML-KEM/Kyber, ML-DSA/Dilithium), manteniendo
la misma interfaz (keygen / commit / open) para no romper `smart_token.token`.
"""

from __future__ import annotations
import numpy as np


def lwe_keygen(n: int = 64, q: int = 3329, sigma: float = 2.0, seed=None):
    """
    Genera una instancia LWE de juguete.
    A: matriz pública (n x n)
    s: secreto (mantenido por el emisor/verificador del token)
    b = A s + e (mod q) — recuperar s desde (A, b) es el problema difícil (LWE).
    """
    rng = np.random.default_rng(seed)
    A = rng.integers(0, q, size=(n, n))
    s = rng.integers(0, q, size=n)
    e = np.round(rng.normal(0, sigma, size=n)).astype(int) % q
    b = (A @ s + e) % q
    return A, b, s


def lwe_commit(A: np.ndarray, b: np.ndarray, message_bits: list[int], q: int = 3329, rng=None):
    """Compromiso tipo Regev de cada bit del mensaje usando la instancia pública (A, b)."""
    n = A.shape[0]
    if rng is None:
        rng = np.random.default_rng()
    commitments = []
    for bit in message_bits:
        r = rng.integers(0, 2, size=n)
        u = (A.T @ r) % q
        v = (int(b @ r) + bit * (q // 2)) % q
        commitments.append((u, v))
    return commitments


def lwe_open(commitments, s: np.ndarray, q: int = 3329) -> list[int]:
    """Sólo quien tiene el secreto s puede abrir los compromisos."""
    recovered = []
    for u, v in commitments:
        pred = (v - int(u @ s)) % q
        dist_to_half = min(abs(pred - q // 2), q - abs(pred - q // 2))
        bit = 1 if dist_to_half < q // 4 else 0
        recovered.append(bit)
    return recovered
