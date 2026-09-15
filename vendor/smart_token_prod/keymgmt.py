"""
Gestión de claves.

Hoy SmartTokenProd genera sk/pk de ML-KEM y las guarda como atributos
del objeto Python, en memoria de proceso, sin rotación ni control de
acceso. Suficiente para un prototipo; no para producción.

Este módulo define la interfaz que separa "generar/usar la clave" de
"dónde y cómo vive esa clave", para poder enchufar después un HSM/KMS
real sin tocar la lógica de SmartTokenProd. Nadie puede terminar esa
parte por ti dentro de este entorno: un HSM/AWS KMS/GCP KMS/Vault
requiere una cuenta, credenciales y una decisión de proveedor que son
tuyas.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Tuple


class KeyProvider(ABC):
    """Contrato para cualquier fuente de claves ML-KEM."""

    @abstractmethod
    def get_or_create_keypair(self, key_id: str) -> Tuple[bytes, bytes]:
        """Devuelve (public_key, secret_key) para key_id, creando si no existe."""

    @abstractmethod
    def decapsulate(self, key_id: str, ciphertext: bytes) -> bytes:
        """
        Realiza la decapsulación SIN exponer la clave secreta a quien llama.
        En un HSM real, esta operación ocurre dentro del hardware y la
        secret key nunca sale de él.
        """

    @abstractmethod
    def rotate(self, key_id: str) -> Tuple[bytes, bytes]:
        """Genera un nuevo par de claves para key_id y lo hace el activo."""


import time

class InMemoryKeyProvider(KeyProvider):
    """
    Backend de referencia con política opcional de rotación por tiempo o uso.
    (sk/pk en memoria de proceso). Válido para desarrollo y pruebas.
    """

    def __init__(self, max_age_seconds: float = 0.0, max_uses: int = 0):
        from . import core as _core
        self._core = _core
        self._keys: dict[str, Tuple[bytes, bytes]] = {}
        self._created_at: dict[str, float] = {}
        self._use_count: dict[str, int] = {}
        self.max_age_seconds = max_age_seconds
        self.max_uses = max_uses

    def _should_rotate(self, key_id: str) -> bool:
        if key_id not in self._keys:
            return False
        if self.max_uses > 0 and self._use_count.get(key_id, 0) >= self.max_uses:
            return True
        if self.max_age_seconds > 0.0 and (time.time() - self._created_at.get(key_id, 0.0)) >= self.max_age_seconds:
            return True
        return False

    def get_or_create_keypair(self, key_id: str) -> Tuple[bytes, bytes]:
        if key_id not in self._keys or self._should_rotate(key_id):
            return self.rotate(key_id)
        return self._keys[key_id]

    def decapsulate(self, key_id: str, ciphertext: bytes) -> bytes:
        if key_id not in self._keys:
            raise KeyError(f"key_id desconocido: {key_id!r}")
        if self._should_rotate(key_id):
            self.rotate(key_id)
            raise ValueError(f"La clave {key_id!r} ha rotado automáticamente por política de expiración y ya no puede desencapsular paquetes antiguos.")
        _, sk = self._keys[key_id]
        self._use_count[key_id] = self._use_count.get(key_id, 0) + 1
        return self._core.mlkem_decaps(sk, ciphertext)

    def rotate(self, key_id: str) -> Tuple[bytes, bytes]:
        self._keys[key_id] = self._core.mlkem_keygen()
        self._created_at[key_id] = time.time()
        self._use_count[key_id] = 0
        return self._keys[key_id]


class HsmKeyProvider(KeyProvider):
    """
    Placeholder deliberado — NO funcional.

    Integrar un HSM/KMS real (AWS KMS, GCP KMS, Azure Key Vault, un HSM
    on-prem via PKCS#11) requiere que tú:
      1. Elijas el proveedor (depende de dónde vaya a vivir el producto).
      2. Crees la cuenta/hardware y las credenciales.
      3. Verifiques que el proveedor soporte las primitivas ML-KEM que
         usas (a la fecha, el soporte de KEMs post-cuánticos en HSMs
         comerciales es limitado — esto hay que confirmarlo con cada
         proveedor, no es algo que se pueda asumir).

    Este método está aquí solo para dejar visible el contrato al que
    tendría que ajustarse esa integración cuando la hagas.
    """

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "HsmKeyProvider requiere credenciales y un proveedor real de KMS/HSM "
            "que solo tú puedes decidir y configurar fuera de este entorno."
        )

    def get_or_create_keypair(self, key_id: str) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def decapsulate(self, key_id: str, ciphertext: bytes) -> bytes:
        raise NotImplementedError

    def rotate(self, key_id: str) -> Tuple[bytes, bytes]:
        raise NotImplementedError
