"""
Motor de Descubrimiento Estructural por Transformada de Walsh-Hadamard y Residuos.
Extrae hipótesis no lineales de alto orden (grado 2..4+) sobre banderas de telemetría de agentes.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from itertools import combinations
from typing import Optional, List, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

@dataclass
class StructuralHypothesis:
    variables: tuple
    degree: int
    coefficient: float
    mean_abs_walsh: float
    support_rate: float
    mean_delta_auc: float
    interpretation: str

@dataclass
class StructuralReport:
    n_cases: int
    n_flags: int
    baseline_auc: float
    enriched_auc: float
    hypotheses: list
    candidates_evaluated: int

    def summary(self, top_k: int = 15):
        print("=" * 72)
        print("AOM-QUANTUM ENGINE — STRUCTURAL DISCOVERY REPORT")
        print("=" * 72)
        print(f"Casos: {self.n_cases} | Banderas: {self.n_flags}")
        print(f"AUC baseline:   {self.baseline_auc:.4f}")
        print(f"AUC estructural:{self.enriched_auc:.4f}")
        print(f"Delta AUC:      {self.enriched_auc - self.baseline_auc:+.4f}")
        print(f"Candidatos:     {self.candidates_evaluated}")
        print("\nHIPÓTESIS ESTRUCTURALES")
        for h in self.hypotheses[:top_k]:
            print(f"  {h.variables} | orden={h.degree} | "
                  f"coef={h.coefficient:+.3f} | "
                  f"estabilidad={h.support_rate:.0%} | "
                  f"ΔAUC={h.mean_delta_auc:+.4f}")
            print(f"    {h.interpretation}")

def discover_structure(
    X: np.ndarray,
    y: np.ndarray,
    flag_names: Optional[list] = None,
    max_degree: int = 4,
    folds: int = 5,
    min_support: float = 0.60,
    top_per_degree: int = 8,
    random_state: int = 42,
) -> StructuralReport:
    """
    Descubre interacciones binarias no lineales proyectando sobre la base de Walsh-Hadamard S = 1 - 2*X.
    """
    X = np.asarray(X, dtype=int)
    y = np.asarray(y, dtype=int)
    n = X.shape[1]
    if flag_names is None:
        flag_names = [f"F{i}" for i in range(n)]
    if len(flag_names) != n:
        raise ValueError("flag_names no coincide con la dimensión de X")
    if len(np.unique(y)) < 2:
        raise ValueError(
            "discover_structure requiere al menos dos clases en y (eventos marcados "
            "y no marcados). Con una sola clase no hay nada que discriminar -- "
            "revisa tus datos de entrada antes de interpretar cualquier resultado."
        )

    S = 1 - 2 * X
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=random_state)
    baseline_pred = np.zeros(len(y))
    fold_terms = []
    candidate_count = 0

    for tr, te in skf.split(X, y):
        base = LogisticRegression(max_iter=3000).fit(X[tr], y[tr])
        residual = y[tr] - base.predict_proba(X[tr])[:, 1]
        scored = []
        for d in range(2, max_degree + 1):
            for term in combinations(range(n), d):
                score = float(abs(np.mean(residual * np.prod(S[tr][:, term], axis=1))))
                scored.append((score, term))
        candidate_count += len(scored)
        scored.sort(reverse=True)
        fold_terms.append(scored)

        baseline_pred[te] = base.predict_proba(X[te])[:, 1]

    baseline_auc = float(roc_auc_score(y, baseline_pred))

    stats = {}
    for scored in fold_terms:
        bydeg = {}
        for score, t in scored:
            bydeg.setdefault(len(t), []).append((score, t))
        for d, vals in bydeg.items():
            for score, t in vals[:top_per_degree]:
                if t not in stats:
                    stats[t] = []
                stats[t].append(score)

    hypotheses = []
    for term, scores in stats.items():
        support = len(scores) / folds
        if support < min_support:
            continue
        deltas = []
        for tr, te in skf.split(X, y):
            Ftr = np.column_stack([X[tr][:, i] for i in range(n)] + [np.prod(S[tr][:, term], axis=1)])
            Fte = np.column_stack([X[te][:, i] for i in range(n)] + [np.prod(S[te][:, term], axis=1)])
            m = LogisticRegression(max_iter=3000).fit(Ftr, y[tr])
            p = m.predict_proba(Fte)[:, 1]
            b = LogisticRegression(max_iter=3000).fit(X[tr], y[tr])
            pb = b.predict_proba(X[te])[:, 1]
            deltas.append(float(roc_auc_score(y[te], p) - roc_auc_score(y[te], pb)))
        coeff = float(np.mean(scores))
        delta = float(np.mean(deltas))
        names = tuple(flag_names[i] for i in term)
        interpretation = (
            "La señal de anomalía estructural emerge cuando estas banderas actúan conjuntamente; "
            "interacción binaria no lineal de alto orden."
        )
        hypotheses.append(
            StructuralHypothesis(names, len(term), coeff, coeff, support, delta, interpretation)
        )

    hypotheses.sort(
        key=lambda h: (h.support_rate, h.mean_delta_auc, h.mean_abs_walsh), reverse=True
    )

    stable_terms = [
        tuple(flag_names.index(v) for v in h.variables) for h in hypotheses
    ]
    if stable_terms:
        cols = [X[:, i] for i in range(n)] + [np.prod(S[:, t], axis=1) for t in stable_terms]
        F = np.column_stack(cols)
        enriched_pred = np.zeros(len(y))
        for tr, te in skf.split(F, y):
            m = LogisticRegression(max_iter=3000).fit(F[tr], y[tr])
            enriched_pred[te] = m.predict_proba(F[te])[:, 1]
        enriched_auc = float(roc_auc_score(y, enriched_pred))
    else:
        enriched_auc = baseline_auc

    return StructuralReport(len(y), n, baseline_auc, enriched_auc, hypotheses, candidate_count)
