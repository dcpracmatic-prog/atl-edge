"""
Long-lived artifact protection for ATL Edge.

This module integrates SmartTokenProd (ML-KEM-768 + AES-256-GCM bound to
master_secret + sequential friction + .stok file format) as a complementary
capability next to the short-lived ATLP data-plane packages.

Design rules (non-negotiable):
- ATLP remains the canonical sealer for short-lived, node-bound packages that
  travel to the premium connector.
- SmartTokenProd is used for artifacts that must survive longer, leave the
  node, or require a human master_secret + out-of-band sk + file-local friction.
- SmartTokenProd **requires pqcrypto** to operate. The native friction core
  (libfriction.so) is an optional performance/hardening backend; if it is
  absent, a pure-Python SequentialTarpit is used automatically. Protection
  does not depend on the native library.
- "Persistent friction" means the friction snapshot is stored inside the
  authenticated .stok header (HMAC keyed by master_secret). It is **not** a
  distributed/multi-worker counter; concurrent workers need an external
  FrictionStore to share state.
- All public functions degrade gracefully when pqcrypto is unavailable;
  callers receive a clear error instead of a partial/unsafe path.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_PKG = Path(__file__).resolve().parents[1]

# Smart Token Prod is a real installed dependency, pinned in requirements.txt to
# a tag of github.com/dcpracmatic-prog/Smart-Token-Prod. It used to be a copy
# under vendor/ reached by inserting that directory on sys.path, which is how the
# data room ended up reporting 0.4.4 while the tree carried 0.4.5. There is no
# sys.path manipulation here on purpose: if the package is missing, this module
# reports unavailable instead of silently importing a stale copy.

# ---------------------------------------------------------------------------
# Availability probe
# ---------------------------------------------------------------------------
SMART_TOKEN_PROD_OK = False
_STP_IMPORT_ERROR: Optional[str] = None

try:
    from smart_token_prod import (  # type: ignore
        protect_file,
        open_stok,
        read_stok,
        friction_status,
        SmartTokenProd,
        __version__ as STP_VERSION,
    )
    from smart_token_prod.native import is_available as native_friction_available

    # 0.10.x publishes a supported façade (smart_token_prod.sdk, re-exported by
    # smart_token_bridge.py). Use its readiness probe when present: it also
    # checks argon2/cryptography, which a bare import does not.
    try:
        from smart_token_prod.sdk import is_available as _sdk_is_available

        if not _sdk_is_available():
            raise ImportError("smart_token_prod.sdk reports the crypto stack unavailable")
    except ImportError as exc:
        if "crypto stack unavailable" in str(exc):
            raise
        # Older builds without .sdk: the plain import above is the probe.

    SMART_TOKEN_PROD_OK = True
except Exception as exc:  # pragma: no cover - environment dependent
    SMART_TOKEN_PROD_OK = False
    _STP_IMPORT_ERROR = str(exc)
    STP_VERSION = "unavailable"
    protect_file = open_stok = read_stok = friction_status = SmartTokenProd = None  # type: ignore
    def native_friction_available() -> bool:  # type: ignore
        return False


def is_available() -> bool:
    """True when the SmartTokenProd stack can be imported and used."""
    return SMART_TOKEN_PROD_OK


def status() -> Dict[str, Any]:
    """Diagnostic snapshot for operators and self-tests."""
    return {
        "smart_token_prod_available": SMART_TOKEN_PROD_OK,
        "version": STP_VERSION,
        "native_friction_available": bool(native_friction_available()) if SMART_TOKEN_PROD_OK else False,
        "import_error": _STP_IMPORT_ERROR,
        "role": (
            "long-lived file protection (complementary to ATLP short-lived packages)"
            if SMART_TOKEN_PROD_OK
            else "unavailable"
        ),
    }


# ---------------------------------------------------------------------------
# Public API — functional, not conceptual
# ---------------------------------------------------------------------------
def protect_artifact(
    input_path: str | Path,
    *,
    master_secret: bytes | str,
    output_path: str | Path | None = None,
    key_path: str | Path | None = None,
    public_label: bytes = b"ATL-EDGE-LONG-LIVED",
    tarpit_mode: str = "cpu",
    tarpit_seconds: float = 1.5,
    friction_backend: str = "auto",
) -> Tuple[Path, Path]:
    """
    Protect a file for long-lived storage / transfer using SmartTokenProd.

    Returns (stok_path, key_path). The .stok file does **not** contain the
    ML-KEM secret key; that lives only in the sibling .stok.key file.

    Raises RuntimeError if SmartTokenProd cannot be loaded.
    """
    if not SMART_TOKEN_PROD_OK:
        raise RuntimeError(
            "SmartTokenProd is not available. Install its dependencies "
            f"(pqcrypto, cryptography). Import error was: {_STP_IMPORT_ERROR}"
        )
    if isinstance(master_secret, str):
        master_secret = master_secret.encode("utf-8")
    return protect_file(
        input_path,
        output_path=output_path,
        master_secret=master_secret,
        public_label=public_label,
        tarpit_mode=tarpit_mode,
        tarpit_seconds=tarpit_seconds,
        friction_backend=friction_backend,
        key_path=key_path,
    )


def open_artifact(
    stok_path: str | Path,
    *,
    master_secret: bytes | str,
    key_path: str | Path | None = None,
    output_path: str | Path | None = None,
    update_friction: bool = True,
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """
    Attempt to open a long-lived .stok artifact.

    Returns (plaintext_or_None, info_dict). On failure the info dict contains
    friction state and the reason; friction is persisted when update_friction
    is True.
    """
    if not SMART_TOKEN_PROD_OK:
        raise RuntimeError(
            "SmartTokenProd is not available. Install its dependencies "
            f"(pqcrypto, cryptography). Import error was: {_STP_IMPORT_ERROR}"
        )
    if isinstance(master_secret, str):
        master_secret = master_secret.encode("utf-8")
    return open_stok(
        stok_path,
        master_secret=master_secret,
        key_path=key_path,
        output_path=output_path,
        update_friction=update_friction,
    )


def artifact_friction_status(stok_path: str | Path) -> Dict[str, Any]:
    """Return the persisted friction snapshot of a .stok file."""
    if not SMART_TOKEN_PROD_OK:
        raise RuntimeError(
            "SmartTokenProd is not available. "
            f"Import error was: {_STP_IMPORT_ERROR}"
        )
    return friction_status(stok_path)


__all__ = [
    "is_available",
    "status",
    "protect_artifact",
    "open_artifact",
    "artifact_friction_status",
    "SMART_TOKEN_PROD_OK",
    "STP_VERSION",
]
