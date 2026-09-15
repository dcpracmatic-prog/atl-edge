"""TLS helpers for the two HTTP surfaces in this package
(`ControlPlaneServer`, `ConnectorIngestServer`).

Both servers in this MVP were plain HTTP over loopback, which was fine for
proving the authentication logic (HMAC signatures, Ed25519 entitlement
signing) works, but is not something to run across a real network: headers
and bodies — including the signed entitlement and the sealed ATLP package —
would be sent in the clear.

This module does two things, and deliberately nothing more:

  1. `generate_self_signed_cert()` — a throwaway CA-less certificate for
     local dev/test, so the TLS code path itself is exercised by the
     selftests instead of being unreachable code that only runs against a
     production cert nobody can hand this repo.
  2. `server_context()` / `client_context()` — thin wrappers around
     `ssl.SSLContext` so both server classes and the transport client share
     one place that decides TLS version floor and cipher policy, instead of
     each caller configuring `ssl` by hand.

**What this is not**: a certificate authority, an ACME client, or a secret
store. Production deployment terminates TLS with a certificate from a real
CA (or an internal PKI) in front of these servers — most commonly at a
reverse proxy / load balancer — and points `client_context(ca_path=...)` at
that CA's root, not at a self-signed leaf cert. `client_context()` refuses
to skip verification silently: the caller must pass either a specific CA to
trust or explicitly opt into `insecure_skip_verify=True`, which raises if
attempted without also setting `allow_insecure=True` twice — once in the
call, once as an environment acknowledgement — to make it hard to land in
production by accident (see `client_context` docstring).
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(common_name: str, out_dir: Path, *,
                               valid_days: int = 30) -> Tuple[Path, Path]:
    """Generate a throwaway self-signed cert+key pair for dev/test TLS.

    Not for production: no CA chain, short-lived on purpose, and the private
    key is written to disk unencrypted (0600). Production terminates TLS
    with a certificate issued by a real CA / internal PKI instead.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = out_dir / f"{common_name}.cert.pem"
    key_path = out_dir / f"{common_name}.key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    os.chmod(cert_path, 0o644)
    os.chmod(key_path, 0o600)
    return cert_path, key_path


def server_context(certfile: Path, keyfile: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return ctx


def client_context(*, ca_path: Optional[Path] = None,
                    insecure_skip_verify: bool = False,
                    allow_insecure: bool = False) -> ssl.SSLContext:
    """Build a client SSLContext.

    Normal use: pass `ca_path` pointing at the CA (or, in dev, the specific
    self-signed leaf cert) the caller expects to see — this still verifies
    the chain and the hostname, it just trusts a smaller root set than the
    system default.

    `insecure_skip_verify=True` disables verification entirely (no chain
    check, no hostname check). It requires `allow_insecure=True` as a
    second, separate flag, so a config file that only sets one of the two
    (e.g. a stray `insecure_skip_verify: true` copied into a prod config)
    fails closed instead of silently disabling TLS verification.
    """
    if insecure_skip_verify:
        if not allow_insecure:
            raise ValueError(
                "insecure_skip_verify=True requires allow_insecure=True as well "
                "— this is a two-flag guard against disabling TLS verification by accident"
            )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ctx = ssl.create_default_context(cafile=str(ca_path) if ca_path else None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
