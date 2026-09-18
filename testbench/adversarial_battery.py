#!/usr/bin/env python3
"""
Adversarial battery for SmartTokenProd.

Produces structured evidence that the security-relevant properties hold
(or clearly records where the environment cannot exercise them).

Attack scenarios covered
------------------------
A1  Key-binding: possession of ML-KEM ss (i.e. sk) is not enough to decrypt
    without the correct master_secret.
A2  .stok serialization never embeds the ML-KEM secret key (sk).
A3  Wrong master_secret → closed failure + friction advancement.
A4  Missing sk / key file → closed failure + friction advancement.
A5  Ciphertext / AAD tampering → AES-GCM authentication failure, no payload.
A6  Low-level bypass attempt (derive key from ss only) fails against a
    payload sealed with the bound derivation.
A7  Friction state persists across independent open_stok calls (file-backed).
A8  Legitimate path still recovers the original payload.
A9  Coherence / material mismatch fails closed.\nA10 Tampered friction_snapshot fails header MAC.\nA11 Tampered public_label fails header MAC.\nA12 Tampered salt fails header MAC.\nA15 Mixed .stok A + .stok.key B fails closed.\nA17 Truncated .stok fails closed.

The battery is intentionally self-contained and CI-friendly: it never
assumes pqcrypto is present. Cases that require the full stack are marked
SKIPPED with a reason when the dependency is missing.

Phase-3 hang and this battery
-----------------------------
Smart Token Prod >= 0.10.0 answers a DENIED open at ``fail_count >= 3`` with a
deliberate, silent, **non-returning** grind (``phase3_blocking_grind``). That is
correct product behaviour against an attacker, and it makes an assertion-based
battery hang forever: several cases here intentionally fail an open three or more
times and then need to *inspect* the DENIED result.

So the harness disables the non-returning grind via the package's own documented
switch, ``SMART_TOKEN_PHASE3_HANG=0``. This does not weaken anything under test:
fail-closed behaviour, friction persistence, header MACs and key binding are all
still exercised at full strength, and Argon2id still runs at its real cost. Only
the *unbounded sleep* is turned off, and only inside the harness.

That the grind actually engages in the default configuration is verified
separately and with a bound, by ``testbench/phase3_hang_probe.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

# Must be set before smart_token_prod is imported anywhere below. See the module
# docstring: without this the battery blocks forever in the phase-3 grind.
# setdefault, so an operator can still force it back on explicitly.
os.environ.setdefault("SMART_TOKEN_PHASE3_HANG", "0")
import tempfile
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Path bootstrap (works from repo root or testbench/)
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parents[1]
# smart_token_prod is an installed dependency now (pinned in requirements.txt);
# there is no vendor/ copy left to put on sys.path.
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ---------------------------------------------------------------------------
# Pure primitives used even when pqcrypto is absent
# ---------------------------------------------------------------------------
def _derive_aes_key_bound(shared_secret: bytes, master_secret: bytes,
                          info: bytes = b"SMART-TOKEN-AES") -> bytes:
    """Canonical bound derivation (must match core.py)."""
    return hashlib.sha256(shared_secret + b"|MS|" + master_secret + info).digest()


def _derive_aes_key_unbound(shared_secret: bytes,
                            info: bytes = b"SMART-TOKEN-AES") -> bytes:
    """Old vulnerable derivation (ss only) — used as the attacker model."""
    return hashlib.sha256(shared_secret + info).digest()


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------
@dataclass
class CaseResult:
    id: str
    title: str
    # PASS | FAIL | SKIP | N/A
    #   SKIP = this host cannot exercise the case (missing dependency). It is a
    #          gap in the evidence, so --require-full treats it as a failure.
    #   N/A  = the property does not exist in this format/version by design, so
    #          there is nothing to prove here on any host. Reported separately
    #          because calling it a PASS would be a lie and calling it a SKIP
    #          would make --require-full permanently unsatisfiable.
    status: str
    detail: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


@dataclass
class BatteryReport:
    started_at: str
    finished_at: str = ""
    environment: Dict[str, Any] = field(default_factory=dict)
    cases: List[CaseResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.cases if c.status == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for c in self.cases if c.status == "FAIL")

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.cases if c.status == "SKIP")

    @property
    def not_applicable(self) -> int:
        return sum(1 for c in self.cases if c.status == "N/A")

    def summary(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "not_applicable": self.not_applicable,
            "total": len(self.cases),
            "ok": self.failed == 0,
        }


def _run_case(case_id: str, title: str, fn: Callable[[], Dict[str, Any]]) -> CaseResult:
    t0 = time.perf_counter()
    try:
        evidence = fn() or {}
        status = evidence.pop("_status", "PASS")
        detail = evidence.pop("_detail", "")
        return CaseResult(
            id=case_id,
            title=title,
            status=status,
            detail=detail,
            evidence=evidence,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    except Exception as exc:
        return CaseResult(
            id=case_id,
            title=title,
            status="FAIL",
            detail=f"uncaught exception: {exc}",
            evidence={"traceback": traceback.format_exc()},
            duration_ms=(time.perf_counter() - t0) * 1000,
        )


# ---------------------------------------------------------------------------
# Availability of the full SmartTokenProd stack
# ---------------------------------------------------------------------------
def _probe_stack() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "smart_token_prod_importable": False,
        "pqcrypto": False,
        "cryptography": False,
        "native_friction": False,
        "version": None,
        "error": None,
    }
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        info["cryptography"] = True
    except Exception as e:
        info["error"] = f"cryptography: {e}"
        return info

    try:
        import pqcrypto  # noqa: F401
        info["pqcrypto"] = True
    except Exception:
        pass

    try:
        from smart_token_prod import (
            protect_file,
            open_stok,
            __version__,
        )
        from smart_token_prod.native import is_available as native_ok
        info["smart_token_prod_importable"] = True
        info["version"] = __version__
        info["native_friction"] = bool(native_ok())
    except Exception as e:
        info["error"] = str(e)
    return info


# ===========================================================================
# Adversarial cases
# ===========================================================================
def case_a1_key_binding_property() -> Dict[str, Any]:
    """A1 — Bound derivation: ss alone must not yield the real AES key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ss = os.urandom(32)
    master = b"correct-master-secret-for-a1"
    wrong = b"attacker-guess"

    real_key = _derive_aes_key_bound(ss, master)
    attacker_key = _derive_aes_key_bound(ss, wrong)
    unbound_key = _derive_aes_key_unbound(ss)

    assert real_key != attacker_key
    assert real_key != unbound_key

    aes = AESGCM(real_key)
    nonce = os.urandom(12)
    pt = b"adversarial-payload-a1"
    ct = aes.encrypt(nonce, pt, b"aad-a1")

    # Attacker with wrong master
    try:
        AESGCM(attacker_key).decrypt(nonce, ct, b"aad-a1")
        return {"_status": "FAIL", "_detail": "decrypt succeeded with wrong master_secret"}
    except Exception as e:
        wrong_err = type(e).__name__

    # Attacker using old unbound derivation (the pre-0.4.3 bug model)
    try:
        AESGCM(unbound_key).decrypt(nonce, ct, b"aad-a1")
        return {"_status": "FAIL", "_detail": "decrypt succeeded with unbound (ss-only) key"}
    except Exception as e:
        unbound_err = type(e).__name__

    # Legitimate key still works
    recovered = AESGCM(real_key).decrypt(nonce, ct, b"aad-a1")
    assert recovered == pt

    return {
        "real_key_prefix": real_key[:8].hex(),
        "attacker_key_prefix": attacker_key[:8].hex(),
        "unbound_key_prefix": unbound_key[:8].hex(),
        "wrong_master_error": wrong_err,
        "unbound_error": unbound_err,
        "legitimate_recover_ok": True,
    }


def case_a6_low_level_bypass_model() -> Dict[str, Any]:
    """A6 — Explicit model of the old bypass: seal with bound key, attack with ss-only."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ss = os.urandom(32)
    master = b"master-a6"
    bound = _derive_aes_key_bound(ss, master)
    unbound = _derive_aes_key_unbound(ss)

    nonce = os.urandom(12)
    pt = b"sealed-under-bound-derivation"
    ct = AESGCM(bound).encrypt(nonce, pt, b"")

    try:
        AESGCM(unbound).decrypt(nonce, ct, b"")
        return {
            "_status": "FAIL",
            "_detail": "ss-only key decrypted a bound ciphertext — binding is broken",
        }
    except Exception as e:
        return {
            "bypass_blocked": True,
            "error": type(e).__name__,
            "bound_eq_unbound": bound == unbound,
        }


def _full_stack_or_skip() -> Optional[Dict[str, Any]]:
    env = _probe_stack()
    if not env["smart_token_prod_importable"] or not env["pqcrypto"]:
        return {
            "_status": "SKIP",
            "_detail": f"full stack unavailable ({env.get('error') or 'pqcrypto missing'})",
            "environment": env,
        }
    return None


def _fails_closed(pt: Any, info: Dict[str, Any]) -> bool:
    """Did this open fail closed, under the >=0.10 opaque-DENIED contract?

    Up to 0.4.5 the battery asserted ``info["recoverable"] is False`` or
    ``info["header_mac_ok"] is False``. Since 0.10 a denied open is deliberately
    **opaque**: those keys are stripped so the result cannot be used as an
    oracle for *why* it was refused (see OPAQUE_DENY_KEYS upstream). Asserting on
    them now silently inverts the test — a correctly denied open returns None for
    every one of them, which the old expression read as failure.

    So the observable contract is exactly this: no plaintext, and a DENIED
    status. That is also the only thing an attacker gets to see, which is the
    property we actually care about.
    """
    if pt is not None:
        return False
    status = info.get("status") if isinstance(info, dict) else None
    # Owner-visible paths (reveal_friction=True) may still expose the details;
    # accept either shape rather than demanding opacity where it is not required.
    if status == "DENIED":
        return True
    return info.get("recoverable") is False or info.get("header_mac_ok") is False


def _field_is_persisted(stok: Any, field: str) -> bool:
    """Is `field` actually carrying bytes in this .stok format version?

    ``salt`` and ``material`` are empty in .stok v2 on purpose: upstream demoted
    coherence to a public-view metric precisely so it could not act as an
    authorization oracle. Tampering an empty field is a vacuous test that would
    "pass" no matter what the library does, so cases that target these fields
    check this first and SKIP with a reason instead of pretending to prove
    something. If a future format starts persisting them again, the same cases
    become real assertions automatically.
    """
    value = getattr(stok, field, None)
    return bool(value)


def case_a2_sk_not_in_stok() -> Dict[str, Any]:
    """A2 — Serialized .stok must not contain the ML-KEM secret key."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, read_stok

    with tempfile.TemporaryDirectory(prefix="a2-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a2")
        stok_path, key_path = protect_file(
            src, master_secret=b"master-a2", public_label=b"A2"
        )
        stok = read_stok(stok_path)
        raw = stok_path.read_bytes()
        key_raw = key_path.read_bytes()

        # Structural checks
        has_sk_attr = getattr(stok, "sk", None) is not None
        # Raw file should not contain an obvious "sk" JSON field with key material
        # (format uses base64 fields; we check the public dict contract)
        public = stok.to_dict()
        sk_in_public = "sk" in public

        return {
            "stok_has_sk_attribute_set": has_sk_attr,
            "sk_in_serialized_dict": sk_in_public,
            "key_file_exists": key_path.is_file(),
            "key_file_size": len(key_raw),
            "stok_size": len(raw),
            "pass_criteria": "sk_in_serialized_dict == False and key_file_exists",
            "_status": "PASS" if (not sk_in_public and key_path.is_file()) else "FAIL",
            "_detail": (
                ""
                if not sk_in_public and key_path.is_file()
                else "sk leaked into .stok or key file missing"
            ),
        }


def case_a3_wrong_master() -> Dict[str, Any]:
    """A3 — Wrong master_secret must not open (header MAC / coherence fail closed)."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok

    with tempfile.TemporaryDirectory(prefix="a3-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a3")
        stok_path, key_path = protect_file(src, master_secret=b"correct-master")

        pt, info = open_stok(
            stok_path,
            master_secret=b"wrong-master",
            key_path=key_path,
            update_friction=True,
        )
        # A wrong master_secret cannot derive the AES key, so it must never
        # return plaintext. Since 0.10 the refusal is opaque, so the assertion is
        # "no plaintext + DENIED" rather than a specific failure reason.
        ok = _fails_closed(pt, info)
        return {
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "opaque": info.get("recoverable") is None,
            "info_keys": sorted(info.keys()),
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "wrong master opened the artifact",
        }


def case_a4_missing_sk() -> Dict[str, Any]:
    """A4 — Missing key file must fail closed and record friction."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, friction_status

    with tempfile.TemporaryDirectory(prefix="a4-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a4")
        stok_path, key_path = protect_file(src, master_secret=b"master-a4")
        # Do not pass key_path; also remove the default sibling if present
        if key_path.is_file():
            key_path.unlink()

        # >=0.10 surfaces an absent key file as FileNotFoundError from
        # read_key_file rather than folding it into a DENIED result. Both shapes
        # are fail-closed; what matters is that no plaintext comes back. A
        # missing local key file is an operator configuration fault, not an
        # attacker probe, so raising is arguably the better contract — but the
        # case has to accept it explicitly instead of crashing the battery.
        raised = None
        pt, info = None, {}
        try:
            pt, info = open_stok(
                stok_path,
                master_secret=b"master-a4",
                key_path=tmp / "nonexistent.key",
                update_friction=True,
            )
        except FileNotFoundError as e:
            raised = type(e).__name__

        fr = friction_status(stok_path)
        ok = raised is not None or _fails_closed(pt, info)
        return {
            "raised": raised,
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "friction_fail_count": fr.get("fail_count"),
            "_status": "PASS" if ok else "FAIL",
            "_detail": (
                f"missing sk fails closed via {raised}" if raised
                else ("" if ok else "missing sk did not fail closed")
            ),
        }


def case_a5_tamper_ciphertext() -> Dict[str, Any]:
    """A5 — Bit-flip on ciphertext must produce authentication failure."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, read_stok, write_stok

    with tempfile.TemporaryDirectory(prefix="a5-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a5-secret")
        stok_path, key_path = protect_file(src, master_secret=b"master-a5")

        stok = read_stok(stok_path)
        # Flip first byte of ciphertext
        ct = bytearray(stok.ciphertext)
        ct[0] ^= 0xFF
        stok.ciphertext = bytes(ct)
        write_stok(stok, stok_path)

        pt, info = open_stok(
            stok_path,
            master_secret=b"master-a5",
            key_path=key_path,
        )
        ok = _fails_closed(pt, info)
        return {
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "opaque": info.get("aes_gcm_ok") is None,
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "tampered ciphertext was accepted",
        }


def case_a7_friction_persistence() -> Dict[str, Any]:
    """A7 — Friction must survive across separate open_stok invocations.

    Uses correct master_secret (so header MAC verifies) and force_failure /
    missing-key style failures so the friction path is exercised and rewritten
    with an updated MAC.
    """
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, friction_status

    with tempfile.TemporaryDirectory(prefix="a7-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a7")
        stok_path, key_path = protect_file(src, master_secret=b"master-a7")

        counts = []
        for i in range(3):
            open_stok(
                stok_path,
                master_secret=b"master-a7",
                key_path=key_path,
                force_failure=True,
                update_friction=True,
            )
            fr = friction_status(stok_path)
            snap = fr.get("friction_snapshot") or fr
            counts.append(int(snap.get("fail_count", -1)))

        monotonic = all(counts[i] <= counts[i + 1] for i in range(len(counts) - 1))
        advanced = counts[-1] >= 3
        ok = monotonic and advanced
        return {
            "fail_counts": counts,
            "monotonic": monotonic,
            "reached_at_least_3": advanced,
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else f"friction did not persist/advance: {counts}",
        }


def case_a8_legitimate_roundtrip() -> Dict[str, Any]:
    """A8 — Honest path must recover the exact payload."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok

    payload = b"legitimate-payload-" + os.urandom(32)
    with tempfile.TemporaryDirectory(prefix="a8-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(payload)
        stok_path, key_path = protect_file(src, master_secret=b"master-a8")
        pt, info = open_stok(
            stok_path,
            master_secret=b"master-a8",
            key_path=key_path,
        )
        ok = pt == payload and info.get("recoverable") is True
        return {
            "payload_match": pt == payload,
            "recoverable": info.get("recoverable"),
            "aes_gcm_ok": info.get("aes_gcm_ok"),
            "payload_len": len(payload),
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "legitimate open failed or payload mismatch",
        }


def case_a9_coherence_mismatch() -> Dict[str, Any]:
    """A9 — Material/coherence mismatch must fail closed."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, read_stok, write_stok

    with tempfile.TemporaryDirectory(prefix="a9-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a9")
        stok_path, key_path = protect_file(src, master_secret=b"master-a9")

        stok = read_stok(stok_path)
        if not _field_is_persisted(stok, "material"):
            return {
                "_status": "N/A",
                "_detail": (
                    "material is empty in .stok v2 by design — coherence is a "
                    "public-view metric, not an authorization oracle (upstream "
                    "v0.9). Tampering an empty field proves nothing, so this is "
                    "skipped rather than reported as a pass."
                ),
                "material_len": len(stok.material or b""),
                "format_version": getattr(stok, "version", None),
            }

        # Format persists material again: hold it to fail-closed.
        stok.material = os.urandom(len(stok.material))
        write_stok(stok, stok_path)

        pt, info = open_stok(
            stok_path,
            master_secret=b"master-a9",
            key_path=key_path,
        )
        ok = _fails_closed(pt, info)
        return {
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "coherence mismatch did not fail closed",
        }


# ===========================================================================
# Runner
# ===========================================================================

def case_a10_tamper_friction_snapshot() -> Dict[str, Any]:
    """A10 — Forged friction_snapshot without master_secret must fail header MAC."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, read_stok, write_stok

    with tempfile.TemporaryDirectory(prefix="a10-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a10")
        stok_path, key_path = protect_file(src, master_secret=b"master-a10")

        # Advance friction legitimately so the snapshot is non-trivial
        for _ in range(3):
            open_stok(
                stok_path,
                master_secret=b"master-a10",
                key_path=key_path,
                force_failure=True,
                update_friction=True,
            )

        stok = read_stok(stok_path)
        # Attacker resets friction without knowing master_secret (forges snapshot)
        stok.friction_snapshot = {
            "fail_count": 0,
            "flag_fibonacci": False,
            "flag_persistencia": False,
            "tarpit_triggered": False,
            "fib_seed": 0,
        }
        # Intentionally do NOT recompute header_mac
        write_stok(stok, stok_path)

        pt, info = open_stok(stok_path, master_secret=b"master-a10", key_path=key_path)
        # friction_mac (HMAC over the on-disk snapshot + pk + ct) is what catches
        # this now; the old header_mac is gone. The refusal is opaque either way.
        ok = _fails_closed(pt, info)
        return {
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "opaque": info.get("friction_mac_ok") is None,
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "forged friction_snapshot was accepted",
        }


def case_a11_tamper_metadata_label() -> Dict[str, Any]:
    """A11 — Tampering public_label must fail closed.

    0.4.5 caught this with `header_mac`, which covered public_label. That field is
    gone in v2. Under >=0.10.3 the property is enforced cryptographically
    instead: the AEAD associated data is derived from public_label and recomputed
    from disk at open time, so a forged label yields InvalidTag.

    This case is the one that found the 0.10.2 P0 (upstream v0.10.3): between
    0.4.5 and 0.10.2 the stored `aad` was passed to the AEAD verbatim, so a
    forged public_label opened cleanly with status=OPEN.
    """
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, read_stok, write_stok

    with tempfile.TemporaryDirectory(prefix="a11-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a11")
        stok_path, key_path = protect_file(src, master_secret=b"master-a11")
        stok = read_stok(stok_path)
        stok.public_label = b"TAMPERED-LABEL"
        write_stok(stok, stok_path)
        pt, info = open_stok(stok_path, master_secret=b"master-a11", key_path=key_path)
        ok = _fails_closed(pt, info)
        return {
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "tampered public_label accepted",
        }


def case_a15_mix_stok_and_key() -> Dict[str, Any]:
    """A15 — .stok A + .stok.key B must fail closed."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok

    with tempfile.TemporaryDirectory(prefix="a15-") as tmp:
        tmp = Path(tmp)
        a = tmp / "a.bin"; a.write_bytes(b"payload-A")
        b = tmp / "b.bin"; b.write_bytes(b"payload-B")
        stok_a, key_a = protect_file(a, master_secret=b"master-A", output_path=tmp / "a.stok", key_path=tmp / "a.stok.key")
        stok_b, key_b = protect_file(b, master_secret=b"master-B", output_path=tmp / "b.stok", key_path=tmp / "b.stok.key")

        # Mix: open A with key B (and master A — still must fail on mlkem/aes)
        pt, info = open_stok(stok_a, master_secret=b"master-A", key_path=key_b)
        ok = _fails_closed(pt, info)
        return {
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "opaque": info.get("aes_gcm_ok") is None,
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "mixed stok/key pair was accepted",
        }


def case_a12_tamper_salt() -> Dict[str, Any]:
    """A12 — Tampering salt breaks header MAC (and coherence)."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, read_stok, write_stok
    import os as _os

    with tempfile.TemporaryDirectory(prefix="a12-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"; src.write_bytes(b"payload-a12")
        stok_path, key_path = protect_file(src, master_secret=b"master-a12")
        stok = read_stok(stok_path)
        if not _field_is_persisted(stok, "salt"):
            return {
                "_status": "N/A",
                "_detail": (
                    "salt is empty in .stok v2 by design — the KDF salt lives in "
                    "kdf_params and coherence is a public-view metric, not an "
                    "authorization oracle (upstream v0.9). Tampering an empty "
                    "field proves nothing, so this is skipped rather than "
                    "reported as a pass."
                ),
                "salt_len": len(stok.salt or b""),
                "format_version": getattr(stok, "version", None),
            }

        stok.salt = _os.urandom(len(stok.salt))
        write_stok(stok, stok_path)
        pt, info = open_stok(stok_path, master_secret=b"master-a12", key_path=key_path)
        ok = _fails_closed(pt, info)
        return {
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "tampered salt accepted",
        }


def case_a18_self_consistent_label_forgery() -> Dict[str, Any]:
    """A18 — Forging public_label *and* the stored aad together must still fail.

    A11 alone cannot distinguish a real cryptographic binding from a mere
    consistency check between two fields the attacker controls. Here the attacker
    rewrites public_label and recomputes the stored `aad` to match, which defeats
    any implementation that only compares the two. It must still fail closed,
    because the AEAD tag was produced over the original label.
    """
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok, read_stok, write_stok

    try:
        from smart_token_prod.core import expected_aad
    except ImportError:
        return {
            "_status": "N/A",
            "_detail": (
                "smart_token_prod.core.expected_aad is absent — the installed "
                "version predates the v0.10.3 AAD rebinding, so this forgery "
                "cannot be constructed against the canonical derivation."
            ),
        }

    with tempfile.TemporaryDirectory(prefix="a18-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"
        src.write_bytes(b"payload-a18-secret")
        stok_path, key_path = protect_file(src, master_secret=b"master-a18")

        forged = b"FORGED-LABEL-A18"
        stok = read_stok(stok_path)
        original_label = bytes(stok.public_label)
        stok.public_label = forged
        stok.aad = expected_aad(forged)  # keep the header self-consistent
        write_stok(stok, stok_path)

        pt, info = open_stok(stok_path, master_secret=b"master-a18", key_path=key_path)
        ok = _fails_closed(pt, info)
        return {
            "original_label": original_label.decode("utf-8", "replace"),
            "forged_label": forged.decode(),
            "stored_aad_matches_forged_label": True,
            "plaintext_is_none": pt is None,
            "status": info.get("status"),
            "_status": "PASS" if ok else "FAIL",
            "_detail": "" if ok else "self-consistent label forgery was accepted",
        }


def case_a17_truncated_file() -> Dict[str, Any]:
    """A17 — Truncated .stok must raise / fail closed."""
    skip = _full_stack_or_skip()
    if skip:
        return skip

    from smart_token_prod import protect_file, open_stok

    with tempfile.TemporaryDirectory(prefix="a17-") as tmp:
        tmp = Path(tmp)
        src = tmp / "doc.bin"; src.write_bytes(b"payload-a17")
        stok_path, key_path = protect_file(src, master_secret=b"master-a17")
        data = stok_path.read_bytes()
        stok_path.write_bytes(data[: max(4, len(data) // 3)])
        try:
            pt, info = open_stok(stok_path, master_secret=b"master-a17", key_path=key_path)
            # If it returns, must not be recoverable
            ok = pt is None
            return {
                "raised": False,
                "plaintext_is_none": pt is None,
                "recoverable": info.get("recoverable") if isinstance(info, dict) else None,
                "_status": "PASS" if ok else "FAIL",
                "_detail": "" if ok else "truncated file produced plaintext",
            }
        except Exception as e:
            return {
                "raised": True,
                "error_type": type(e).__name__,
                "_status": "PASS",
                "_detail": "truncated file rejected with exception",
            }


CASES = [
    ("A1", "Key binding: ss alone cannot decrypt (property)", case_a1_key_binding_property),
    ("A6", "Low-level bypass model (unbound vs bound)", case_a6_low_level_bypass_model),
    ("A2", ".stok does not embed sk", case_a2_sk_not_in_stok),
    ("A3", "Wrong master_secret fails + friction", case_a3_wrong_master),
    ("A4", "Missing sk fails + friction", case_a4_missing_sk),
    ("A5", "Ciphertext tampering fails closed", case_a5_tamper_ciphertext),
    ("A7", "Friction persistence across opens", case_a7_friction_persistence),
    ("A8", "Legitimate round-trip", case_a8_legitimate_roundtrip),
    ("A9", "Coherence/material mismatch fails closed", case_a9_coherence_mismatch),
    ("A10", "Tampered friction_snapshot fails friction MAC", case_a10_tamper_friction_snapshot),
    ("A11", "Tampered public_label fails closed (AAD rebind)", case_a11_tamper_metadata_label),
    ("A12", "Tampered salt fails closed", case_a12_tamper_salt),
    ("A15", "Mixed .stok A + key B fails closed", case_a15_mix_stok_and_key),
    ("A18", "Self-consistent public_label forgery fails closed", case_a18_self_consistent_label_forgery),
    ("A17", "Truncated .stok fails closed", case_a17_truncated_file),
]


def run_battery() -> BatteryReport:
    report = BatteryReport(
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        environment=_probe_stack(),
    )
    for case_id, title, fn in CASES:
        result = _run_case(case_id, title, fn)
        report.cases.append(result)
    report.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return report


def render_human(report: BatteryReport) -> str:
    lines = [
        "=" * 72,
        "SmartTokenProd — Adversarial Battery Report",
        "=" * 72,
        f"Started : {report.started_at}",
        f"Finished: {report.finished_at}",
        f"Environment: {json.dumps(report.environment, indent=2)}",
        "",
    ]
    for c in report.cases:
        lines.append(f"[{c.status:4}] {c.id}  {c.title}  ({c.duration_ms:.1f} ms)")
        if c.detail:
            lines.append(f"         detail: {c.detail}")
        if c.evidence and c.status not in ("SKIP", "N/A"):
            # Compact evidence
            ev = {k: v for k, v in c.evidence.items() if not k.startswith("_")}
            lines.append(f"         evidence: {json.dumps(ev, default=str)}")
        lines.append("")
    s = report.summary()
    lines.append("-" * 72)
    lines.append(
        f"SUMMARY  passed={s['passed']}  failed={s['failed']}  "
        f"skipped={s['skipped']}  n/a={s['not_applicable']}  "
        f"total={s['total']}  ok={s['ok']}"
    )
    lines.append("=" * 72)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="SmartTokenProd adversarial battery")
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="Write full machine-readable report to PATH",
    )
    parser.add_argument(
        "--require-full",
        action="store_true",
        help="Exit non-zero if any case was SKIPPED (full stack required)",
    )
    args = parser.parse_args(argv)

    report = run_battery()
    print(render_human(report))

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "started_at": report.started_at,
                    "finished_at": report.finished_at,
                    "environment": report.environment,
                    "summary": report.summary(),
                    "cases": [asdict(c) for c in report.cases],
                },
                indent=2,
                default=str,
            )
        )
        print(f"\nJSON report written to {path}")

    if report.failed:
        return 1
    # Only environment-driven SKIPs block --require-full. N/A cases are properties
    # the current .stok format deliberately does not have, so no host could ever
    # turn them green and gating on them would make this flag unsatisfiable
    # forever. They are printed and counted separately so the distinction is
    # visible rather than buried.
    if args.require_full and report.skipped:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
