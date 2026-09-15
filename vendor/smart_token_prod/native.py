"""
FFI bridge Python <-> C++ (libfriction.so) via ctypes.

Envuelve la API C plana declarada en cpp/friction_core.hpp:
    st_tarpit_create / st_tarpit_destroy
    st_tarpit_register_failure / st_tarpit_reset / st_tarpit_snapshot
    st_coherence_metric

Uso:
    from smart_token_prod.native import NativeTarpit, native_coherence_metric

    t = NativeTarpit(base_key_32_bytes, mode="cpu", tarpit_seconds=1.0)
    t.register_failure()
    snap = t.snapshot()   # dict, misma forma que SequentialTarpit.snapshot() en Python
    t.reset()

Si libfriction.so no está compilado o no se encuentra, `is_available()`
devuelve False y SmartTokenProd cae automáticamente al tarpit puro-Python
(smart_token_prod.core.SequentialTarpit) — la integración es opcional,
nunca un requisito duro.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

_LIB_CANDIDATES = (
    # Next to this module (after build / CI copy)
    os.path.join(os.path.dirname(__file__), "libfriction.so"),
    # Sources live in vendor/smart_token_prod/cpp/
    os.path.join(os.path.dirname(__file__), "cpp", "libfriction.so"),
    # Fallback
    "libfriction.so",
)


class StFrictionSnapshot(ctypes.Structure):
    _fields_ = [
        ("fail_count", ctypes.c_int32),
        ("flag_fibonacci", ctypes.c_int32),
        ("flag_persistencia", ctypes.c_int32),
        ("fib_seed", ctypes.c_int32),
        ("tarpit_triggered", ctypes.c_int32),
        ("working_key", ctypes.c_uint8 * 32),
    ]


def _load_library() -> Optional[ctypes.CDLL]:
    for candidate in _LIB_CANDIDATES:
        try:
            lib = ctypes.CDLL(candidate)
        except OSError:
            continue
        # st_tarpit_create(const uint8_t*, const char*, double) -> void*
        lib.st_tarpit_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_double]
        lib.st_tarpit_create.restype = ctypes.c_void_p

        lib.st_tarpit_destroy.argtypes = [ctypes.c_void_p]
        lib.st_tarpit_destroy.restype = None

        lib.st_tarpit_register_failure.argtypes = [ctypes.c_void_p]
        lib.st_tarpit_register_failure.restype = None

        lib.st_tarpit_reset.argtypes = [ctypes.c_void_p]
        lib.st_tarpit_reset.restype = None

        lib.st_tarpit_snapshot.argtypes = [ctypes.c_void_p, ctypes.POINTER(StFrictionSnapshot)]
        lib.st_tarpit_snapshot.restype = None

        lib.st_coherence_metric.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.st_coherence_metric.restype = ctypes.c_double
        return lib
    return None


_LIB = _load_library()


def is_available() -> bool:
    """True si libfriction.so se cargó y expone la API C esperada."""
    return _LIB is not None


class NativeUnavailableError(RuntimeError):
    """Se intentó usar el backend nativo pero libfriction.so no está disponible."""


class NativeTarpit:
    """
    Envoltura ctypes de smart_token::SequentialTarpit (C++).

    Misma semántica que smart_token_prod.core.SequentialTarpit, pero la
    máquina de estados de fricción, la mutación de clave y el tarpit de
    CPU se ejecutan en código nativo compilado.
    """

    def __init__(self, base_key: bytes, tarpit_mode: str = "cpu", tarpit_seconds: float = 1.5):
        if _LIB is None:
            raise NativeUnavailableError(
                "libfriction.so no encontrado. Compile el núcleo nativo con "
                "`cd cpp && make` (o `make asan` para builds instrumentados) "
                "y asegúrese de que la biblioteca quede en smart_token_prod/ "
                "o en el path de búsqueda. El backend Python puro sigue disponible."
            )
        if len(base_key) != 32:
            raise ValueError(f"base_key debe tener 32 bytes, recibido {len(base_key)}")

        self._base_key = base_key
        self._handle = _LIB.st_tarpit_create(base_key, tarpit_mode.encode(), float(tarpit_seconds))
        if not self._handle:
            raise RuntimeError("st_tarpit_create devolvió NULL")

    def register_failure(self) -> Dict[str, Any]:
        _LIB.st_tarpit_register_failure(self._handle)
        return self.snapshot()

    def reset(self) -> None:
        _LIB.st_tarpit_reset(self._handle)

    def snapshot(self) -> Dict[str, Any]:
        snap = StFrictionSnapshot()
        _LIB.st_tarpit_snapshot(self._handle, ctypes.byref(snap))
        return {
            "fail_count": snap.fail_count,
            "flag_fibonacci": bool(snap.flag_fibonacci),
            "flag_persistencia": bool(snap.flag_persistencia),
            "tarpit_triggered": bool(snap.tarpit_triggered),
            "fib_seed": snap.fib_seed,
        }

    def current_key(self) -> bytes:
        snap = StFrictionSnapshot()
        _LIB.st_tarpit_snapshot(self._handle, ctypes.byref(snap))
        return bytes(snap.working_key)

    def close(self) -> None:
        if getattr(self, "_handle", None):
            _LIB.st_tarpit_destroy(self._handle)
            self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def native_coherence_metric(material: bytes, salt: bytes) -> float:
    if _LIB is None:
        raise NativeUnavailableError("libfriction.so no encontrado.")
    return float(_LIB.st_coherence_metric(material, len(material), salt, len(salt)))
