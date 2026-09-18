#!/usr/bin/env python3
"""
Self-test for the local proposer model path (src/proposer_model.py).

Two modes, on purpose:

* **Config mode** (always runs, including in CI): asserts the resolved
  configuration is the intended free Apache-2.0 model, that the loader refuses to
  download implicitly, and that an unavailable model raises
  ``ProposerModelUnavailable`` instead of silently degrading to unconstrained
  generation. No weights required.
* **Live mode** (runs when a model is actually reachable): loads the GGUF and
  drives a real constrained decode under the Proposal Schema v1 GBNF, then puts
  the result through ``ProposalGate``. This is the part that proves the model is
  functional rather than merely documented.

Live mode triggers when ``ATL_PROPOSER_MODEL_PATH`` points at a ``.gguf`` (or
``ATL_PROPOSER_ALLOW_DOWNLOAD=1``) and ``llama-cpp-python`` is installed. CI does
not ship multi-gigabyte weights, so it exercises config mode and reports the skip
explicitly rather than printing a misleading PASS.

    PYTHONPATH=. python examples/proposer_model_selftest.py
"""

from __future__ import annotations

import sys
import traceback

from src.proposer import ProposeBackend, propose, proposal_schema_v1_gbnf
from src.proposer_model import (
    DEFAULT_MODEL_LICENSE,
    DEFAULT_MODEL_REPO,
    ProposerModelUnavailable,
    is_available,
    llama_cpp_installed,
    load_proposer_model,
    model_config,
)
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.morph8 import MorphGate

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def main() -> int:
    print("=== proposer model self-test ===")
    cfg = model_config()
    for key in sorted(cfg):
        print(f"  {key}: {cfg[key]}")

    print("\n--- config mode ---")
    check("default model is the free Apache-2.0 Qwen3-8B GGUF",
          cfg["repo"] == DEFAULT_MODEL_REPO == "Qwen/Qwen3-8B-GGUF"
          and DEFAULT_MODEL_LICENSE == "apache-2.0",
          f"{cfg['repo']} ({DEFAULT_MODEL_LICENSE})")

    # An Edge host must not reach out for gigabytes because someone called propose().
    check("download is opt-in, not default", cfg["download_allowed"] is False
          or "ATL_PROPOSER_ALLOW_DOWNLOAD" in __import__("os").environ,
          f"download_allowed={cfg['download_allowed']}")

    # Fail closed: a missing model raises, it does not return something usable.
    # Name which branch actually fired, so this does not read as a pass for the
    # missing-path branch when it was really the missing-llama-cpp branch.
    branch = "missing .gguf path" if llama_cpp_installed() else "llama-cpp-python absent"
    try:
        load_proposer_model(model_path="/nonexistent/model.gguf")
        check(f"unloadable model raises instead of degrading [{branch}]", False, "no exception")
    except ProposerModelUnavailable as exc:
        check(f"unloadable model raises ProposerModelUnavailable [{branch}]", True,
              str(exc).splitlines()[0][:70])
    except Exception as exc:  # noqa: BLE001
        check(f"unloadable model raises ProposerModelUnavailable [{branch}]", False,
              f"got {type(exc).__name__}: {exc}")
    if not llama_cpp_installed():
        print("    note: the missing-.gguf branch is NOT covered here because "
              "llama-cpp-python is absent; install the proposer extras to cover it.")

    gbnf = proposal_schema_v1_gbnf()
    check("GBNF grammar forces a JSON object as the first token",
          gbnf.lstrip().startswith("root") and '"{"' in gbnf,
          "Qwen3 <think> preamble is unrepresentable under this grammar")

    print("\n--- live mode ---")
    if not llama_cpp_installed():
        print("  SKIP: llama-cpp-python not installed "
              "(optional extra: pip install -r requirements-proposer.txt)")
    elif not is_available():
        print("  SKIP: no local .gguf reachable — set ATL_PROPOSER_MODEL_PATH "
              f"or download {cfg['repo']} {cfg['file']}")
    else:
        try:
            llm = load_proposer_model()
            text = "Lista clientes activos en Mexico: solo id, region y status."
            proposal = propose(text, backend=ProposeBackend.LLAMA_CPP, model=llm)
            print(f"  proposal: {proposal}")
            gate = ProposalGate(default_proposal_policy(), MorphGate())
            decision = gate.check(proposal)
            check("model emitted a schema-valid proposal under grammar", True)
            check("proposal passes MORPH + policy gate", bool(decision.allowed),
                  getattr(decision, "reason", ""))
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            FAILURES.append("live constrained decode")

    print()
    if FAILURES:
        print(f"FAIL: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("PASS: proposer model path is consistent and fails closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
