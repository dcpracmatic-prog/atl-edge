"""
Compilación opcional del kernel C de aceleración bitwise.

Principio de diseño: el paquete DEBE funcionar al 100% en Python puro,
sin compilador instalado. El kernel C es un modo "performance" opcional,
nunca un requisito de instalación. Si la compilación falla por cualquier
razón, se usa el fallback Python en silencio (o con un solo mensaje si
AGENTGUARD_VERBOSE_BUILD=1).
"""

from __future__ import annotations
import os
import platform
import subprocess
import ctypes
from typing import Optional


def _verbose() -> bool:
    return os.environ.get("AGENTGUARD_VERBOSE_BUILD", "0") == "1"


def _c_kernel_disabled() -> bool:
    return os.environ.get("AGENTGUARD_DISABLE_C_KERNEL", "0") == "1"


def get_library_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "_kernel.dll"
    elif system == "Darwin":
        return "_kernel.dylib"
    else:
        return "_kernel.so"


def _core_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core"))


def get_library_path() -> str:
    return os.path.join(_core_dir(), get_library_name())


def build_kernel() -> bool:
    core_dir = _core_dir()
    src_c = os.path.join(core_dir, "kernel.c")
    output_lib = get_library_path()

    if not os.path.exists(src_c):
        return False

    system = platform.system()
    try:
        if system == "Windows":
            cmd = ["cl", "/LD", "/O2", src_c, f"/Fe:{output_lib}"]
        elif system == "Darwin":
            cmd = ["clang", "-O3", "-dynamiclib", "-fPIC", src_c, "-o", output_lib]
        else:
            cmd = ["gcc", "-O3", "-shared", "-fPIC", src_c, "-o", output_lib]

        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        ok = os.path.exists(output_lib)
        if ok and _verbose():
            print(f"[agentguard] kernel C compilado -> {output_lib}")
        return ok
    except Exception as e:
        if _verbose():
            print(f"[agentguard] kernel C no disponible ({e}); usando fallback Python puro.")
        return False


def ensure_compiled_kernel() -> Optional[ctypes.CDLL]:
    """Intenta cargar el kernel C. Devuelve None sin lanzar excepción si no
    está disponible -- el resto del paquete debe tratar None como 'usar
    fallback Python', nunca como error fatal."""
    if _c_kernel_disabled():
        return None

    lib_path = get_library_path()
    if not os.path.exists(lib_path):
        try:
            build_kernel()
        except Exception:
            return None

    if os.path.exists(lib_path):
        try:
            lib = ctypes.CDLL(lib_path)
            lib.evaluate_agent_friction.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
            lib.evaluate_agent_friction.restype = ctypes.c_uint64
            lib.analyze_swar_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            lib.analyze_swar_buffer.restype = ctypes.c_double
            lib.swar_match_byte_64.argtypes = [ctypes.c_uint64, ctypes.c_uint8]
            lib.swar_match_byte_64.restype = ctypes.c_uint64
            return lib
        except Exception:
            return None
    return None
