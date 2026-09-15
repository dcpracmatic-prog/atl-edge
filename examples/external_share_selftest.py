"""Adversarial-flavored selftest for src/external_share.py — mirrors the
style of examples/licensing_selftest.py and covers the same shape of cases
TDCP's own test suite lists in its README (authorization separation,
tampering, replay, revocation, view-once, bypass attempts)."""
import hashlib

from src.external_share import (
    ExternalShareGatekeeper,
    ExternalShareOracle,
    RecipientIdentity,
)


def _fp(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def main():
    oracle = ExternalShareOracle()
    gate = ExternalShareGatekeeper(oracle)

    partner_cred = "partner-webauthn-cred-001"
    recipient = RecipientIdentity(
        kind="human",
        identifier="auditor@partner-firm.example",
        organization="Partner Firm LLC",
        credential_fingerprint=_fp(partner_cred),
    )

    plaintext = b"quarterly figures - external audit copy"
    sealed = gate.seal(
        plaintext, package_id="pkg-audit-q3", recipient=recipient,
        view_once=False, max_grants=3, ttl_seconds=3600,
    )
    package = sealed["package"]

    # 1. Legitimate open with the correct credential succeeds.
    opened = gate.open(package, credential_fingerprint=_fp(partner_cred), nonce="n1")
    assert opened == plaintext, "legitimate recipient could not open the package"

    # 2. Copying the package alone is not authorization: wrong credential is denied.
    try:
        gate.open(package, credential_fingerprint=_fp("attacker-guess"), nonce="n2")
        raise AssertionError("wrong credential should have been denied")
    except ValueError:
        pass

    # 3. Replaying the same request nonce is denied even with the right credential.
    try:
        gate.open(package, credential_fingerprint=_fp(partner_cred), nonce="n1")
        raise AssertionError("replayed nonce should have been denied")
    except ValueError:
        pass

    # 4. Tampering with the ciphertext (bit flip) breaks AEAD authentication.
    tampered = dict(package)
    raw = bytearray(__import__("src.external_share", fromlist=["_b64d"])._b64d(package["ciphertext"]))
    raw[0] ^= 0xFF
    tampered["ciphertext"] = __import__("src.external_share", fromlist=["_b64e"])._b64e(bytes(raw))
    try:
        gate.open(tampered, credential_fingerprint=_fp(partner_cred), nonce="n3")
        raise AssertionError("tampered ciphertext should have failed AEAD verification")
    except ValueError:
        pass

    # 5. Tampering with header metadata (recipient_org) breaks AAD authentication,
    #    matching TDCP's "envelope integrity covers the complete security envelope".
    tampered_header = {"header": dict(package["header"]), "ciphertext": package["ciphertext"]}
    tampered_header["header"]["recipient_org"] = "Attacker Org"
    try:
        gate.open(tampered_header, credential_fingerprint=_fp(partner_cred), nonce="n4")
        raise AssertionError("tampered AAD-covered header should have failed")
    except ValueError:
        pass

    # 6. Revocation blocks all future grants immediately, independent of
    #    where copies of the ciphertext already are.
    assert oracle.revoke(sealed["share_id"], reason="engagement ended") is True
    try:
        gate.open(package, credential_fingerprint=_fp(partner_cred), nonce="n5")
        raise AssertionError("revoked share should have been denied")
    except ValueError:
        pass

    # 7. View-once: a second share is consumed after its first successful open.
    oracle2 = ExternalShareOracle()
    gate2 = ExternalShareGatekeeper(oracle2)
    vo_recipient = RecipientIdentity(
        kind="system", identifier="svc-partner-ingest",
        organization="Partner Systems Inc", credential_fingerprint=_fp("svc-key-xyz"),
    )
    vo_sealed = gate2.seal(
        b"one-time payload", package_id="pkg-vo-1", recipient=vo_recipient,
        view_once=True, ttl_seconds=3600,
    )
    first = gate2.open(vo_sealed["package"], credential_fingerprint=_fp("svc-key-xyz"), nonce="vo-1")
    assert first == b"one-time payload"
    try:
        gate2.open(vo_sealed["package"], credential_fingerprint=_fp("svc-key-xyz"), nonce="vo-2")
        raise AssertionError("view-once share should be consumed after first open")
    except ValueError:
        pass

    # 8. Grant-signature forgery: a grant this Oracle never signed must be rejected
    #    even if every field looks otherwise valid (mirrors TDCP's signature-forgery case).
    oracle3 = ExternalShareOracle()
    forged_oracle = ExternalShareOracle()  # different signing key, simulates an attacker's own Oracle
    r3 = RecipientIdentity(kind="human", identifier="x@example.com", organization="X", credential_fingerprint=_fp("k"))
    s3 = ExternalShareGatekeeper(oracle3).seal(b"data", package_id="p3", recipient=r3, ttl_seconds=3600)
    legit = oracle3.request_grant(
        share_id=s3["share_id"], operation="decrypt",
        credential_fingerprint=_fp("k"), nonce="fg-1",
    )
    stolen_grant = legit["grant"]
    # A different Oracle instance (different signing key) must refuse to honor
    # a grant it never signed itself, even though every field looks valid.
    assert forged_oracle.release_wrap_secret(stolen_grant) is None, "wrong Oracle must not honor a grant it never signed"

    # 9. Audit chain integrity holds after all of the above.
    check = oracle.audit.verify_integrity()
    assert check["valid"], f"audit chain broken: {check}"
    check2 = oracle2.audit.verify_integrity()
    assert check2["valid"], f"audit chain broken: {check2}"

    print("external_share selftest: PASS")


if __name__ == "__main__":
    main()
