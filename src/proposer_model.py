"""
Local proposer model loader (constrained decoding backend for ``src.proposer``).

Why this module exists
----------------------
``src.proposer`` is deliberately model-agnostic: the grammar backends take a
``model=`` object and never construct one. That left the repository documenting a
model (TinyLlama-1.1B) that nothing could actually load, so in practice only the
deterministic ``TEMPLATE`` backend ever ran.

This module supplies the missing piece: a real, free, current open-weights model,
loaded through ``llama-cpp-python`` so it can be driven under GBNF grammar.

Default model
-------------
``Qwen/Qwen3-8B-GGUF`` — 8.2B parameters (6.95B non-embedding), 32,768-token
native context, Apache-2.0, published by the Qwen team with llama.cpp
instructions and Q4_K_M/Q5_K_M/Q6_K/Q8_0 quantisations. It replaces the
TinyLlama-1.1B reference: roughly 7x the parameters, and instruction-tuned, which
is what makes constrained JSON emission reliable rather than lucky.

Apache-2.0 matters here beyond cost: the operator can run it on-prem, offline,
without a per-call licence, which is the whole premise of a local proposer next
to the data.

Two notes specific to this model
--------------------------------
1. Qwen3 defaults to *thinking* mode and would normally emit a ``<think>...``
   preamble. Under the Proposal Schema v1 GBNF the first token can only be
   ``{``, so the preamble is not representable and the grammar neutralises
   thinking mode without any extra flag. The grammar is the control, not a
   prompt request.
2. The model is a multi-gigabyte download. This loader therefore **never**
   downloads implicitly: point ``ATL_PROPOSER_MODEL_PATH`` at a local ``.gguf``,
   or opt in with ``ATL_PROPOSER_ALLOW_DOWNLOAD=1``. Same fail-closed posture as
   the rest of the Edge: no surprise network egress from a data-plane host.

None of this widens the permission surface. The model only ever produces a
*proposal*; MORPH-8, ``ProposalGate`` and the field catalog still decide what may
run. A better model makes the operator's phrasing land more often — it does not
buy the model more authority.

Usage
-----
    from src.proposer import ProposeBackend, propose
    from src.proposer_model import load_proposer_model

    llm = load_proposer_model()
    proposal = propose("Lista clientes activos en Mexico: solo id, region y status.",
                       backend=ProposeBackend.LLAMA_CPP, model=llm)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

# Free, Apache-2.0, current, and packaged for llama.cpp by the publisher.
DEFAULT_MODEL_REPO = "Qwen/Qwen3-8B-GGUF"
DEFAULT_MODEL_FILE = "*Q4_K_M.gguf"
DEFAULT_MODEL_LICENSE = "apache-2.0"
DEFAULT_CONTEXT_TOKENS = 4096

# The previous documented reference, kept only so status output can show what
# changed and why.
PREVIOUS_REFERENCE_MODEL = "TinyLlama-1.1B"


class ProposerModelUnavailable(RuntimeError):
    """Raised when no local model can be loaded. Never falls back silently."""


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def model_config() -> Dict[str, Any]:
    """Resolved configuration, for ``/api/status`` and operator diagnostics.

    Contains no secrets and does not load the model.
    """
    local_path = _env("ATL_PROPOSER_MODEL_PATH")
    return {
        "repo": _env("ATL_PROPOSER_MODEL_REPO", DEFAULT_MODEL_REPO),
        "file": _env("ATL_PROPOSER_MODEL_FILE", DEFAULT_MODEL_FILE),
        "license": DEFAULT_MODEL_LICENSE,
        "local_path": local_path,
        "local_path_exists": bool(local_path and Path(local_path).is_file()),
        "context_tokens": int(_env("ATL_PROPOSER_CTX", str(DEFAULT_CONTEXT_TOKENS)) or DEFAULT_CONTEXT_TOKENS),
        "download_allowed": _truthy(_env("ATL_PROPOSER_ALLOW_DOWNLOAD")),
        "llama_cpp_installed": llama_cpp_installed(),
        "replaces_reference_model": PREVIOUS_REFERENCE_MODEL,
    }


def llama_cpp_installed() -> bool:
    try:
        import llama_cpp  # noqa: F401

        return True
    except Exception:
        return False


def is_available() -> bool:
    """True when :func:`load_proposer_model` can succeed without downloading."""
    if not llama_cpp_installed():
        return False
    cfg = model_config()
    return bool(cfg["local_path_exists"] or cfg["download_allowed"])


def load_proposer_model(
    *,
    model_path: Optional[str] = None,
    n_ctx: Optional[int] = None,
    n_gpu_layers: int = 0,
    verbose: bool = False,
    **kwargs: Any,
) -> Any:
    """Load the local GGUF proposer model as a ``llama_cpp.Llama``.

    Resolution order, most explicit first:

    1. ``model_path`` argument
    2. ``ATL_PROPOSER_MODEL_PATH`` (a local ``.gguf``; the offline/air-gapped path)
    3. ``ATL_PROPOSER_MODEL_REPO`` / ``_FILE`` from the Hugging Face hub, but
       ONLY when ``ATL_PROPOSER_ALLOW_DOWNLOAD=1``

    Raises :class:`ProposerModelUnavailable` with an actionable message rather
    than returning a degraded object. Callers that want the deterministic path
    should ask for ``ProposeBackend.TEMPLATE`` explicitly instead of treating a
    load failure as permission to run unconstrained.
    """
    if not llama_cpp_installed():
        raise ProposerModelUnavailable(
            "llama-cpp-python is not installed. It is an optional proposer extra, "
            "kept out of the default Edge runtime on purpose: "
            "pip install -r requirements-proposer.txt"
        )
    from llama_cpp import Llama

    cfg = model_config()
    ctx = int(n_ctx or cfg["context_tokens"])
    path = model_path or cfg["local_path"]

    if path:
        if not Path(path).is_file():
            raise ProposerModelUnavailable(
                f"proposer model not found at {path!r}. Download it once, e.g.:\n"
                f"  huggingface-cli download {cfg['repo']} --include '{cfg['file']}' "
                f"--local-dir ./models\n"
                f"then set ATL_PROPOSER_MODEL_PATH to the .gguf file."
            )
        return Llama(model_path=str(path), n_ctx=ctx, n_gpu_layers=n_gpu_layers,
                     verbose=verbose, **kwargs)

    if not cfg["download_allowed"]:
        raise ProposerModelUnavailable(
            f"no local proposer model configured. This loader does not download "
            f"implicitly, so an Edge host makes no unexpected network egress.\n"
            f"  offline (preferred): set ATL_PROPOSER_MODEL_PATH=/path/to/model.gguf\n"
            f"  or opt in:           ATL_PROPOSER_ALLOW_DOWNLOAD=1 "
            f"(fetches {cfg['repo']} {cfg['file']}, several GB)"
        )

    return Llama.from_pretrained(
        repo_id=str(cfg["repo"]),
        filename=str(cfg["file"]),
        n_ctx=ctx,
        n_gpu_layers=n_gpu_layers,
        verbose=verbose,
        **kwargs,
    )
