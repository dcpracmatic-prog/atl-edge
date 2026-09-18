#!/usr/bin/env python3
"""Self-test for long-lived artifact protection (SmartTokenProd integration).

This exercises the real protect → open path. It requires pqcrypto.
If the dependency is missing the test reports the status and exits 0
with a clear message (so CI that does not install pqcrypto still passes
the "graceful degradation" check).
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Make package importable when run from repo root. smart_token_prod itself is an
# installed dependency now (pinned in requirements.txt); there is no vendor/ copy.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Step 4 below deliberately drives fail_count to 3, and from 0.10 onwards that
# makes the next denied open enter a silent, NON-RETURNING grind against the
# attacker. Correct product behaviour, fatal for an assertion-based self-test, so
# turn off just the unbounded sleep using the package's own documented switch.
# Everything else — Argon2id cost, fail-closed paths, friction persistence — runs
# at full strength. The grind's default-on state is covered by the package's own
# suite (test_work_factor_helpers_unit).
os.environ.setdefault("SMART_TOKEN_PHASE3_HANG", "0")

from src.long_lived_protection import (  # noqa: E402
    is_available,
    status,
    protect_artifact,
    open_artifact,
    artifact_friction_status,
)


def main() -> int:
    print("=== ATL Edge — Long-lived protection self-test ===")
    st = status()
    for k, v in st.items():
        print(f"  {k}: {v}")

    if not is_available():
        print("\nSmartTokenProd not available — graceful degradation OK.")
        print("Install pqcrypto + cryptography + numpy to exercise the full path.")
        return 0

    master = b"atl-edge-test-master-secret-do-not-use-in-prod"
    payload = b"ATL Edge long-lived artifact payload v1\n" + os.urandom(64)

    with tempfile.TemporaryDirectory(prefix="atl-llp-") as tmp:
        tmp_path = Path(tmp)
        src = tmp_path / "artifact.bin"
        src.write_bytes(payload)

        print("\n1. Protecting artifact...")
        stok_path, key_path = protect_artifact(
            src,
            master_secret=master,
            public_label=b"ATL-EDGE-SELFTEST",
        )
        print(f"   stok: {stok_path}")
        print(f"   key : {key_path}")
        assert stok_path.is_file()
        assert key_path.is_file()
        # sk must not appear in the serialized public dict of the .stok
        from smart_token_prod import read_stok
        stok_obj = read_stok(stok_path)
        public = stok_obj.to_dict()
        assert "sk" not in public, "sk leaked into .stok serialization"
        assert getattr(stok_obj, "sk", None) is None

        print("\n2. Legitimate open...")
        pt, info = open_artifact(
            stok_path,
            master_secret=master,
            key_path=key_path,
        )
        assert pt == payload, "round-trip payload mismatch"
        # A successful open is NOT opaque, so these keys are still present.
        assert info.get("recoverable") is True
        print(f"   recoverable={info.get('recoverable')} aes_gcm_ok={info.get('aes_gcm_ok')}")

        print("\n3. Wrong master_secret must fail...")
        pt_bad, info_bad = open_artifact(
            stok_path,
            master_secret=b"wrong-master",
            key_path=key_path,
        )
        assert pt_bad is None
        # Since 0.10 a denied open is deliberately opaque: `recoverable`,
        # `aes_gcm_ok` and friends are stripped so the result cannot be used as
        # an oracle for *why* it was refused. The observable contract is "no
        # plaintext + DENIED", so assert that instead of the old key.
        assert info_bad.get("status") == "DENIED"
        assert info_bad.get("recoverable") is None, "denied open must stay opaque"
        print(f"   status={info_bad.get('status')} (opaque, no plaintext)")

        print("\n4. Friction status after failures...")
        # Provoke a couple more failures so friction advances
        for _ in range(2):
            open_artifact(stok_path, master_secret=b"still-wrong", key_path=key_path)
        fr = artifact_friction_status(stok_path)
        print(f"   friction snapshot: {fr}")

        print("\n5. Open without key must fail and record friction...")
        # Remove default sibling key so no resolution path remains
        if key_path.is_file():
            key_path.unlink()
        # >=0.10 raises FileNotFoundError for an absent key file instead of
        # folding it into a DENIED result. Both are fail-closed; accept either.
        try:
            pt_nokey, info_nokey = open_artifact(
                stok_path,
                master_secret=master,
                key_path=tmp_path / "nonexistent.key",
            )
        except FileNotFoundError as e:
            pt_nokey, info_nokey = None, {"status": f"raised {type(e).__name__}"}
        assert pt_nokey is None or pt_nokey == b""
        print(f"   no-key status={info_nokey.get('status')} (no plaintext)")

    print("\nAll long-lived protection checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
