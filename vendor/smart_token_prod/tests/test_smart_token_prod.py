"""
Suite de pruebas.

Ejecutar con:
    cd SmartTokenProd
    pip install -e ".[dev]"
    pytest -v

Cubre:
  - Ciclo de vida completo del token (cifrado/descifrado, AES-GCM, ML-KEM).
  - Máquina de estados de fricción en backend Python vs backend nativo C++
    (deben coincidir bit a bit para la misma clave).
  - Persistencia del estado de fricción (store en memoria).
  - Proveedor de claves en memoria.

NO cubre (fuera de alcance de pruebas unitarias, ver THREAT_MODEL.md):
  - Resistencia real a side-channels / timing attacks.
  - Comportamiento bajo carga concurrente real (ver benchmarks/).
  - Cualquier cosa que dependa de infraestructura externa (Redis, HSM).
"""

import hashlib

import pytest

from smart_token_prod import SmartTokenProd
from smart_token_prod.core import coherence_metric, governance_fingerprint
from smart_token_prod.native import is_available as native_is_available, native_coherence_metric
from smart_token_prod.persistence import InMemoryFrictionStore, PersistentTarpit
from smart_token_prod.keymgmt import InMemoryKeyProvider


GOVERNANCE = [0, 0, 0, 1, 0, 1, 1, 1]


# ---------------------------------------------------------------------------
# Ciclo de vida del token
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("backend", ["python", "native", "auto"])
def test_open_legitimate_returns_payload(backend):
    tok = SmartTokenProd(
        GOVERNANCE, b"payload-secreto", b"master",
        tarpit_mode="cpu", tarpit_seconds=0.1, friction_backend=backend,
    )
    pt, info = tok.open()
    assert pt == b"payload-secreto"
    assert info["aes_gcm_ok"] is True
    assert info["mlkem_ok"] is True


@pytest.mark.parametrize("backend", ["python", "native", "auto"])
def test_forced_failure_does_not_leak_payload(backend):
    tok = SmartTokenProd(
        GOVERNANCE, b"payload-secreto", b"master",
        tarpit_mode="cpu", tarpit_seconds=0.05, friction_backend=backend,
    )
    pt, info = tok.open(force_failure=True)
    assert pt is None
    assert info["recoverable"] is False
    assert "payload" not in info


@pytest.mark.parametrize("backend", ["python", "native"])
def test_friction_state_machine_progression(backend):
    tok = SmartTokenProd(
        GOVERNANCE, b"x", b"master",
        tarpit_mode="cpu", tarpit_seconds=0.05, friction_backend=backend,
    )
    _, info1 = tok.open(force_failure=True)
    assert info1["friction_state"]["fail_count"] == 1
    assert info1["friction_state"]["flag_fibonacci"] is True
    assert info1["friction_state"]["tarpit_triggered"] is False

    _, info2 = tok.open(force_failure=True)
    assert info2["friction_state"]["fail_count"] == 2
    assert info2["friction_state"]["flag_persistencia"] is True

    _, info3 = tok.open(force_failure=True)
    assert info3["friction_state"]["fail_count"] == 3
    assert info3["friction_state"]["tarpit_triggered"] is True


def test_successful_open_resets_friction():
    tok = SmartTokenProd(
        GOVERNANCE, b"x", b"master",
        tarpit_mode="cpu", tarpit_seconds=0.05, friction_backend="python",
    )
    tok.open(force_failure=True)
    assert tok.friction_snapshot()["fail_count"] == 1
    tok.open()  # apertura legitima
    assert tok.friction_snapshot()["fail_count"] == 0


def test_tampered_ciphertext_fails_aes_gcm():
    tok = SmartTokenProd(GOVERNANCE, b"payload-secreto", b"master", friction_backend="python")
    tok.ciphertext = bytes([tok.ciphertext[0] ^ 0xFF]) + tok.ciphertext[1:]
    pt, info = tok.open()
    assert pt is None
    assert info["aes_gcm_ok"] is False


# ---------------------------------------------------------------------------
# Paridad Python <-> C++ nativo
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not native_is_available(), reason="libfriction.so no compilado/disponible")
def test_native_coherence_matches_python_bit_for_bit():
    material = hashlib.sha256(b"material").digest()
    salt = hashlib.sha256(b"salt").digest()[:16]
    py_value = coherence_metric(material, salt)
    native_value = native_coherence_metric(material, salt)
    assert py_value == pytest.approx(native_value, abs=1e-12)


@pytest.mark.skipif(not native_is_available(), reason="libfriction.so no compilado/disponible")
def test_native_and_python_tarpit_agree_on_fib_seed():
    from smart_token_prod.core import SequentialTarpit
    from smart_token_prod.native import NativeTarpit

    key = hashlib.sha256(b"same-base-key").digest()
    py_tarpit = SequentialTarpit(key, "cpu", 0.05)
    native_tarpit = NativeTarpit(key, "cpu", 0.05)

    py_tarpit.register_failure()
    native_tarpit.register_failure()

    assert py_tarpit.snapshot()["fib_seed"] == native_tarpit.snapshot()["fib_seed"]
    assert py_tarpit.snapshot()["fail_count"] == native_tarpit.snapshot()["fail_count"]


# ---------------------------------------------------------------------------
# Persistencia
# ---------------------------------------------------------------------------

def test_inmemory_friction_store_roundtrip():
    store = InMemoryFrictionStore()
    assert store.load("user-1") is None
    store.save("user-1", {"fail_count": 2})
    assert store.load("user-1") == {"fail_count": 2}
    store.clear("user-1")
    assert store.load("user-1") is None


def test_persistent_tarpit_restores_fail_count_across_instances():
    from smart_token_prod.core import SequentialTarpit

    store = InMemoryFrictionStore()
    key = hashlib.sha256(b"identity-key").digest()

    tarpit_a = PersistentTarpit(SequentialTarpit(key, "cpu", 0.05), store, identity="user-1")
    tarpit_a.register_failure()
    tarpit_a.register_failure()
    assert tarpit_a.snapshot()["fail_count"] == 2

    # Simula un reinicio de proceso / otra instancia: nuevo tarpit, mismo store.
    tarpit_b = PersistentTarpit(SequentialTarpit(key, "cpu", 0.05), store, identity="user-1")
    assert tarpit_b.snapshot()["fail_count"] == 2  # restaurado, no en cero


# ---------------------------------------------------------------------------
# Gestión de claves
# ---------------------------------------------------------------------------

def test_inmemory_key_provider_reuses_keypair_for_same_id():
    provider = InMemoryKeyProvider()
    pk1, sk1 = provider.get_or_create_keypair("token-A")
    pk2, sk2 = provider.get_or_create_keypair("token-A")
    assert pk1 == pk2 and sk1 == sk2


def test_inmemory_key_provider_rotate_changes_keys():
    provider = InMemoryKeyProvider()
    pk1, sk1 = provider.get_or_create_keypair("token-A")
    pk2, sk2 = provider.rotate("token-A")
    assert pk1 != pk2


def test_governance_fingerprint_shape():
    fp = governance_fingerprint(GOVERNANCE)
    assert set(fp.keys()) == {"const", "A", "B", "AB", "C", "AC", "BC", "ABC"}


# ---------------------------------------------------------------------------
# Capa de archivo .stok
# ---------------------------------------------------------------------------

def test_stok_protect_open_roundtrip(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok, friction_status

    sample = tmp_path / "pieza.stl"
    sample.write_bytes(b"solid demo\nendsolid demo\n")
    master = b"test-master-key"

    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_seconds=0.05, friction_backend="python"
    )
    assert stok_path.exists()
    assert key_path.exists()
    assert friction_status(stok_path)["friction_snapshot"]["fail_count"] == 0
    assert friction_status(stok_path)["has_embedded_sk"] is False

    out = tmp_path / "pieza_out.stl"
    pt, info = open_stok(
        stok_path, master_secret=master, key_path=key_path,
        output_path=out, update_friction=True,
    )
    assert pt == sample.read_bytes()
    assert info["recoverable"] is True
    assert out.read_bytes() == sample.read_bytes()


def test_stok_friction_persists_across_opens(tmp_path):
    """Friction advances only when header_mac verifies (correct master).

    Wrong master fails closed via header_mac without rewriting the snapshot.
    Use force_failure with the correct master to exercise persistence + reset.
    """
    from smart_token_prod.stok import protect_file, open_stok, friction_status

    sample = tmp_path / "cad.stl"
    sample.write_bytes(b"binary-stl-placeholder-content-xyz")
    master = b"correct-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_seconds=0.05, friction_backend="python"
    )

    # Wrong master must not open (and cannot rewrite authenticated friction)
    pt, info = open_stok(
        stok_path,
        master_secret=b"wrong-master",
        key_path=key_path,
        update_friction=True,
    )
    assert pt is None
    assert info.get("recoverable") is False
    assert info.get("header_mac_ok") is False

    # Advance friction with correct master + forced failure
    for _ in range(3):
        pt, info = open_stok(
            stok_path,
            master_secret=master,
            key_path=key_path,
            force_failure=True,
            update_friction=True,
        )
        assert pt is None
        assert info["recoverable"] is False

    st = friction_status(stok_path)
    assert st["friction_snapshot"]["fail_count"] == 3
    assert st["friction_snapshot"]["tarpit_triggered"] is True

    # Legitimate open resets friction
    pt, info = open_stok(
        stok_path, master_secret=master, key_path=key_path, update_friction=True
    )
    assert pt == sample.read_bytes()
    assert friction_status(stok_path)["friction_snapshot"]["fail_count"] == 0


def test_stok_without_key_fails(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok

    sample = tmp_path / "x.stl"
    sample.write_bytes(b"payload")
    stok_path, key_path = protect_file(
        sample, master_secret=b"m", tarpit_seconds=0.05, friction_backend="python"
    )
    key_path.unlink()
    pt, info = open_stok(stok_path, master_secret=b"m", update_friction=True)
    assert pt is None
    assert info["recoverable"] is False
    assert "sk no disponible" in (info.get("mlkem_error") or "")
