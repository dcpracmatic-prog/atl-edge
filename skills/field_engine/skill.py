#!/usr/bin/env python3
"""
Skill opcional: FIELD Engine native v2 (path / graph planning)

No forma parte del control plane de agentes (ATL). Es una herramienta
que un agente puede invocar cuando el dominio es un grafo (rutas,
dependencias, hops).

Motor:
  - Dijkstra + memoria de sucesores acotada (MAX_OUT=4)
  - Revalidación contra grafo vivo (aristas borradas no se fabrican)
  - Sintaxis FIELD multi-línea DEFINE/RESOLVE

Uso:
  from skills.field_engine.skill import FieldEngineSkill
  sk = FieldEngineSkill()
  print(sk.selftest_status())
  print(sk.plan_route([10, 50, 90, 200]))  # waypoints
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

_DIR = Path(__file__).resolve().parent
_CPP = _DIR / "field_engine_native_v2.cpp"
_BIN_NAME = "field_engine_v2"


def _find_or_build_binary() -> Optional[Path]:
    # Prefer /tmp (sandbox may mount package noexec)
    candidates = [
        Path("/tmp") / _BIN_NAME,
        _DIR / _BIN_NAME,
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    # build to /tmp
    out = Path("/tmp") / _BIN_NAME
    try:
        subprocess.run(
            ["g++", "-O3", "-std=c++17", str(_CPP), "-o", str(out)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        out.chmod(0o755)
        return out
    except Exception:
        return None


class FieldEngineSkill:
    """Optional agent skill for graph path planning with FIELD memory."""

    def __init__(
        self,
        graph_path: Optional[Path] = None,
        traffic_path: Optional[Path] = None,
    ):
        self.graph_path = Path(graph_path) if graph_path else _DIR / "graph.txt"
        self.traffic_path = Path(traffic_path) if traffic_path else _DIR / "traffic.txt"
        self.binary = _find_or_build_binary()

    @property
    def available(self) -> bool:
        return self.binary is not None and self.graph_path.exists()

    def selftest_status(self) -> Dict[str, Any]:
        if not self.available:
            return {"ok": False, "error": "binary or graph.txt missing"}
        work = Path(tempfile.mkdtemp(prefix="field_eng_"))
        try:
            shutil.copy(self.graph_path, work / "graph.txt")
            shutil.copy(self.traffic_path, work / "traffic.txt")
            r = subprocess.run(
                [str(self.binary)],
                cwd=str(work),
                capture_output=True,
                text=True,
                timeout=180,
            )
            stderr = r.stderr or ""
            stdout = r.stdout or ""
            ok = r.returncode == 0 and "6/6 verificaciones OK" in stderr
            # parse C vs A line if present
            reduction = None
            for line in stdout.splitlines():
                if "C vs A:" in line:
                    reduction = line.strip()
            return {
                "ok": ok,
                "returncode": r.returncode,
                "self_check": "6/6" if ok else "FAIL",
                "summary": reduction,
                "stdout_tail": "\n".join(stdout.strip().splitlines()[-8:]),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def describe(self) -> str:
        return (
            "FIELD Engine v2 skill: plan multi-hop routes on a weighted graph "
            "with successor memory, live-edge revalidation, and DEFINE/RESOLVE "
            "program composition. Use for spatial/dependency path planning; "
            "not for general LLM tool chains."
        )


if __name__ == "__main__":
    sk = FieldEngineSkill()
    print("available:", sk.available)
    print(sk.describe())
    st = sk.selftest_status()
    for k, v in st.items():
        print(f"{k}: {v}")
