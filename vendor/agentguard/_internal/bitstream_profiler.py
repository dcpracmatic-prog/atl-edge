"""
Perfilador adaptativo de streams de bits con remapeo de LUT.

Nota de honestidad técnica: este componente es una heurística de perfilado
de frecuencias sobre bloques de 6 bits (aisla los valores menos frecuentes
como "códigos de escape"). No tiene validación empírica publicada de que
esos códigos correlacionen con fallos reales de agentes -- se ofrece como
señal exploratoria adicional, no como detector probado.
"""

from __future__ import annotations
import gc
import time
import ctypes
import numpy as np
from typing import Tuple, Dict, Any, Optional

POWERS_OF_TWO = np.array([32, 16, 8, 4, 2, 1], dtype=np.uint8)

class AdaptiveBitstreamFSM:
    """
    FSM Adaptativa para profilado y filtrado dinámico de streams de 6 bits.
    Utiliza remapeo de LUT en tiempo real para aislar patrones de escape e inyecta
    el kernel SWAR en C para procesamiento sin latencia.
    """

    def __init__(self, key_pattern: int = 0b101101):
        self.key_pattern = key_pattern
        self.ctrl_vals = None
        self.mask_pattern = np.array(
            [(key_pattern >> (5 - i)) & 1 for i in range(6)], dtype=np.uint8
        )
        from agentguard._internal.builder import ensure_compiled_kernel
        self._libswar = ensure_compiled_kernel()

    def profile_and_remap_lut(self, sample_stream_6b: np.ndarray) -> np.ndarray:
        """
        Profila las frecuencias de bloques de 6 bits y asigna los 12 valores
        de menor frecuencia como estados de control/escape.
        """
        val_bloques = sample_stream_6b @ POWERS_OF_TWO
        conteo_frecuencias = np.bincount(val_bloques, minlength=64)
        indices_menor_frecuencia = np.argsort(conteo_frecuencias)[:12]
        self.ctrl_vals = np.array(indices_menor_frecuencia, dtype=np.uint8)
        return self.ctrl_vals

    def process_stream(
        self, bit_array: np.ndarray, sample_size_blocks: int = 1000
    ) -> Dict[str, Any]:
        """
        Procesa el stream de bits binario desactivando temporalmente GC para prevenir jitter.
        """
        n = len(bit_array)
        valid_len = n - (n % 6)
        if valid_len == 0:
            return {"pct_escape": 0.0, "latency_ms": 0.0, "throughput_mbps": 0.0, "total_escapes": 0}

        gc.disable()
        t_start = time.perf_counter()

        mask_full = np.tile(self.mask_pattern, (valid_len // 6) + 1)[:valid_len]
        stream_fase = bit_array[:valid_len] ^ mask_full
        chunks_6b = stream_fase.reshape(-1, 6)

        sample_blocks = chunks_6b[:sample_size_blocks]
        self.profile_and_remap_lut(sample_blocks)

        val_bloques = chunks_6b @ POWERS_OF_TWO
        escapes_mask = np.isin(val_bloques, self.ctrl_vals)
        total_escapes = int(np.count_nonzero(escapes_mask))

        t_end = time.perf_counter()
        gc.enable()

        latency_ms = (t_end - t_start) * 1000.0
        throughput_mbps = (n / (latency_ms / 1000.0)) / 1e6 if latency_ms > 0 else 0.0
        pct_escape = (total_escapes / len(chunks_6b)) * 100.0

        return {
            "pct_escape": pct_escape,
            "latency_ms": latency_ms,
            "throughput_mbps": throughput_mbps,
            "total_escapes": total_escapes,
            "ctrl_vals": sorted(self.ctrl_vals.tolist()) if self.ctrl_vals is not None else [],
        }

    def swar_fast_match(self, word: int, target_byte: int) -> int:
        """Llama al motor C SWAR branchless si está disponible, o usa fallback."""
        if self._libswar:
            return self._libswar.swar_match_byte_64(ctypes.c_uint64(word), ctypes.c_uint8(target_byte))
        
        # Fallback en Python
        M01 = 0x0101010101010101
        mask_ctrl = 0x8080808080808080
        target_word = M01 * target_byte
        xorw = word ^ target_word
        return (xorw - M01) & ~xorw & mask_ctrl
