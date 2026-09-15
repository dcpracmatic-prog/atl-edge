"""
Persistencia del estado de fricción.

Hoy SequentialTarpit/NativeTarpit viven en RAM: si el proceso se reinicia,
un atacante recupera sus 3 intentos "gratis". En un despliegue real con
más de una instancia (varios workers, autoscaling), cada instancia además
llevaría su propio contador — el atacante puede repartir intentos entre
instancias y nunca disparar el tarpit.

Este módulo define la interfaz que un backend de persistencia debe cumplir
y ofrece:
  - InMemoryFrictionStore: equivalente a lo que hay hoy (para tests/dev).
  - RedisFrictionStore: shape lista para producción, pero requiere que
    TÚ proveas una conexión redis real — este entorno no tiene Redis ni
    puede probarlo contra un servidor de verdad.

No reemplaza a NativeTarpit/SequentialTarpit: los envuelve para que el
snapshot se lea/escriba desde un store compartido, con la clave del
"identity" del token (p. ej. un id de sesión o de usuario).
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class FrictionStore(ABC):
    """Contrato mínimo que cualquier backend de persistencia debe cumplir."""

    @abstractmethod
    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        """Devuelve el último snapshot guardado para `identity`, o None."""

    @abstractmethod
    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        """Guarda el snapshot. ttl_seconds, si se da, expira el registro."""

    @abstractmethod
    def clear(self, identity: str) -> None:
        """Borra el estado de fricción de `identity` (equivalente a reset())."""


class InMemoryFrictionStore(FrictionStore):
    """
    Backend de referencia — mismo comportamiento que hoy (estado en RAM),
    pero ahora detrás de la interfaz FrictionStore para que cambiarlo por
    un backend real (Redis, DynamoDB, Postgres) sea un solo parámetro.

    Útil para tests y para desarrollo local. NO usar en producción
    multi-instancia: no comparte estado entre procesos.
    """

    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
        self._expiry: Dict[str, float] = {}

    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        exp = self._expiry.get(identity)
        if exp is not None and time.time() > exp:
            self._data.pop(identity, None)
            self._expiry.pop(identity, None)
            return None
        return self._data.get(identity)

    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        self._data[identity] = dict(snapshot)
        if ttl_seconds is not None:
            self._expiry[identity] = time.time() + ttl_seconds
        else:
            self._expiry.pop(identity, None)

    def clear(self, identity: str) -> None:
        self._data.pop(identity, None)
        self._expiry.pop(identity, None)


class RedisFrictionStore(FrictionStore):
    """
    Backend listo para producción — NO probado aquí porque este entorno
    no tiene un servidor Redis real ni acceso de red a uno.

    Requiere que le pases un cliente redis-py ya conectado (tú decides
    host, auth, TLS, cluster vs standalone — eso es infraestructura tuya,
    no algo que se pueda resolver en este sandbox).

    Uso:
        import redis
        r = redis.Redis(host="...", port=6379, password="...", ssl=True)
        store = RedisFrictionStore(r, key_prefix="smarttoken:friction:")
    """

    def __init__(self, redis_client, key_prefix: str = "smarttoken:friction:"):
        self._r = redis_client
        self._prefix = key_prefix

    def _key(self, identity: str) -> str:
        return f"{self._prefix}{identity}"

    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        raw = self._r.get(self._key(identity))
        if raw is None:
            return None
        return json.loads(raw)

    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        payload = json.dumps(snapshot)
        if ttl_seconds is not None:
            self._r.setex(self._key(identity), ttl_seconds, payload)
        else:
            self._r.set(self._key(identity), payload)

    def clear(self, identity: str) -> None:
        self._r.delete(self._key(identity))


class PersistentTarpit:
    """
    Envuelve un tarpit (SequentialTarpit o NativeTarpit) para que su
    fail_count sobreviva reinicios y se comparta entre instancias, usando
    cualquier FrictionStore.

    Nota importante: la CLAVE mutada (working_key) del tarpit en memoria
    y la que se guarda en el store pueden divergir si el mismo `identity`
    se autentica desde dos instancias en paralelo (condición de carrera
    inherente a cualquier contador distribuido sin locks). Para producción
    real hace falta decidir la semántica de concurrencia deseada
    (last-write-wins, lock distribuido, etc.) — decisión de arquitectura
    que depende de tu infraestructura, no algo que se resuelva aquí.
    """

    def __init__(self, tarpit, store: FrictionStore, identity: str, ttl_seconds: Optional[int] = None):
        self._tarpit = tarpit
        self._store = store
        self._identity = identity
        self._ttl = ttl_seconds
        self._restore()

    def _restore(self) -> None:
        saved = self._store.load(self._identity)
        if saved and saved.get("fail_count", 0) > 0:
            for _ in range(saved["fail_count"]):
                self._tarpit.register_failure()

    def register_failure(self):
        result = self._tarpit.register_failure()
        self._store.save(self._identity, self._tarpit.snapshot(), self._ttl)
        return result

    def reset(self) -> None:
        self._tarpit.reset()
        self._store.clear(self._identity)

    def snapshot(self) -> Dict[str, Any]:
        return self._tarpit.snapshot()
