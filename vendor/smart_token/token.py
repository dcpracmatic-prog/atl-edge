"""
Smart Token — ensamblaje de capas.

Principio de diseño (no negociable): la capa estructural NUNCA es fuente de
seguridad. Si se elimina o corrompe por completo, el token pierde
interpretabilidad de gobernanza pero el secreto sigue protegido por
`smart_token.lwe`.
"""

from __future__ import annotations
import numpy as np

from .structural import governance_fingerprint, fingerprint_roundtrip_check
from .lwe import lwe_keygen, lwe_commit, lwe_open
try:
    from .discovery import discover_structure
except Exception:
    discover_structure = None  # type: ignore


class SmartTokenV1:
    """Huella determinista (Walsh-Hadamard) + núcleo LWE.

    Útil cuando la política de gobernanza es una tabla FIJA y conocida
    (no aprendida de datos de uso con ruido).
    """

    def __init__(self, governance_outcomes: list[int], secret_bits: list[int], seed=None):
        assert len(governance_outcomes) == 8, "f debe tener 8 valores (Q3 completo)"
        self.fingerprint = governance_fingerprint(governance_outcomes)
        self._structural_ok = fingerprint_roundtrip_check(governance_outcomes)

        A, b, s = lwe_keygen(seed=seed)
        self.public_params = {"A": A, "b": b}
        self._secret = s
        self._rng = np.random.default_rng(seed)
        self.commitment = lwe_commit(A, b, secret_bits, rng=self._rng)

    def verify_and_open(self) -> list[int]:
        return lwe_open(self.commitment, self._secret)

    def public_view(self) -> dict:
        return {
            "governance_fingerprint": self.fingerprint,
            "structural_layer_reversible": self._structural_ok,
            "commitment": self.commitment,
        }


class SmartTokenV2:
    """Huella validada por cross-val (structural_discovery) + núcleo LWE.

    Preferible cuando la política de gobernanza se infiere de datos de uso
    reales (con ruido), en vez de estar definida por una tabla fija.
    """

    def __init__(self, X_usage, y_usage, flag_names, secret_bits: list[int], seed=None,
                 min_support: float = 0.6, min_delta_auc: float = 0.005, max_degree: int = 3):
        report = discover_structure(X_usage, y_usage, flag_names=flag_names,
                                     max_degree=max_degree, folds=5, min_support=min_support)
        self.report = report
        self.validated_fingerprint = [
            {
                "variables": h.variables,
                "degree": h.degree,
                "coefficient": round(h.coefficient, 4),
                "support_rate": h.support_rate,
                "delta_auc": round(h.mean_delta_auc, 4),
            }
            for h in report.hypotheses if h.mean_delta_auc >= min_delta_auc
        ]

        A, b, s = lwe_keygen(seed=seed)
        self.public_params = {"A": A, "b": b}
        self._secret = s
        self._rng = np.random.default_rng(seed)
        self.commitment = lwe_commit(A, b, secret_bits, rng=self._rng)

    def verify_and_open(self) -> list[int]:
        return lwe_open(self.commitment, self._secret)

    def public_view(self) -> dict:
        return {
            "baseline_auc": round(self.report.baseline_auc, 4),
            "enriched_auc": round(self.report.enriched_auc, 4),
            "validated_fingerprint": self.validated_fingerprint,
            "commitment": self.commitment,
        }
