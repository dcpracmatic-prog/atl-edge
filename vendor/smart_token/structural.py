"""
Capa estructural — Walsh-Hadamard sobre Q3 = (Z2)^3.

Advertencia de diseño (importante, léase antes de usar):
Esta capa NO aporta dureza criptográfica. H8 es una transformación lineal
ortogonal, trivialmente invertible (H8 H8^T = 8I). Su función es de
auditabilidad/explicabilidad/compresión de una política de gobernanza,
no de protección de secretos. La seguridad del Smart Token vive
exclusivamente en `smart_token.lwe`.
"""

from __future__ import annotations
import numpy as np

LABELS_Q3 = ["const", "A", "B", "AB", "C", "AC", "BC", "ABC"]


def walsh_hadamard_matrix(n_bits: int = 3) -> np.ndarray:
    """H[r,c] = (-1)^popcount(r AND c)."""
    N = 2 ** n_bits
    H = np.empty((N, N), dtype=int)
    for r in range(N):
        for c in range(N):
            parity = bin(r & c).count("1") % 2
            H[r, c] = 1 if parity == 0 else -1
    return H


def wht_forward(f: np.ndarray, H: np.ndarray) -> np.ndarray:
    return H @ f


def wht_inverse(f_hat: np.ndarray, H: np.ndarray) -> np.ndarray:
    N = H.shape[0]
    return (H @ f_hat) / N


def governance_fingerprint(f: list[int]) -> dict:
    """
    f: 8 valores de gobernanza indexados por combinaciones binarias 000..111.
    Devuelve los coeficientes de Walsh (huella estructural determinista).

    Nota: sobre una tabla fija sin ruido, esta huella SIEMPRE existe, incluso
    si f fuera ruido puro. Para uso sobre datos reales, preferir
    `smart_token.discovery.discover_structure`, que valida señal vs. ruido.
    """
    H = walsh_hadamard_matrix(3)
    f_hat = wht_forward(np.array(f), H)
    return dict(zip(LABELS_Q3, f_hat.tolist()))


def fingerprint_roundtrip_check(f: list[int]) -> bool:
    """Confirma que la capa es reversible (por tanto no es una capa de secreto)."""
    H = walsh_hadamard_matrix(3)
    f_hat = wht_forward(np.array(f), H)
    f_rec = wht_inverse(f_hat, H)
    return bool(np.allclose(f, f_rec))
