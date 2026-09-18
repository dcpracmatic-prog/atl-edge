#!/usr/bin/env python3
"""Build an installable node bundle with a NODE licence.

Roadmap item 6, packaging half. Produces the directory a pilot buyer actually
receives: the stack, a node-bound signed entitlement, the control-plane public
key, and an env file — plus a manifest of exactly what is inside.

What this deliberately does NOT put in the bundle:

  * the control-plane PRIVATE key. It signs licences; shipping it would let the
    buyer mint their own, which is the same as having no licensing at all. It is
    written outside the bundle and the bundle is checked for it.
  * `ATL_MASTER_KEY_HEX`. The master key provisions node keys. A node needs its
    own derived key; a connector needs less than that. Shipping the master with
    the product would make the whole key hierarchy ornamental.

Usage
-----
  python scripts/package_node.py --node-id node-warehouse-01 \\
      --org-id org-buyer --days 90 --catalog inventory --out dist/

  # reuse an existing control-plane key instead of generating one
  python scripts/package_node.py ... --signing-key /secure/cp_private.pem

Verify the result:
  python scripts/package_node.py --verify dist/node-warehouse-01
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.licensing import (  # noqa: E402
    Entitlement,
    EntitlementSigner,
    SignedEntitlement,
    verify_entitlement,
)

# Files the buyer needs to run the node. Kept explicit rather than globbing the
# repo: a bundle built by `cp -r .` is how a private key ends up shipped.
# The first version of this list omitted deploy_edge.sh, so the bundle built,
# audited clean, and then died on first boot with "No such file or directory".
# An explicit list is still right -- a bundle built by `cp -r .` is how a private
# key gets shipped -- but it has to be checked by BOOTING the bundle, which
# --smoke-test now does.
BUNDLE_FILES = [
    "requirements.txt",
    "requirements-proposer.txt",
    "build.sh",
    "atlctl.py",              # deploy_edge.sh bootstraps through this
    "smart_token_bridge.py",
    "iva.md",
    "README.md",
]
BUNDLE_DIRS = [
    "src",
    "vendor",
    "examples",
    "docker",
    "docs",
    "scripts",     # start_stack + deploy_edge + the CI guards the annex cites
    "testbench",   # the annex tells the buyer to run these
    "eo_probe",    # native sources build.sh compiles
    "connector",
    "third_party",
]
# Only the committed CC BY sample travels; the fetched extract does not.
BUNDLE_GLOBS = ["datasets/inventory/*.sample.csv", "datasets/inventory/SOURCE.md"]

# Anything matching these must never appear in a bundle. Matched EXACTLY, not
# by substring: a broad `".env"` check flags the bundle's own `node.env`, and a
# guard that cries wolf on an intended file is a guard that gets switched off.
FORBIDDEN_NAMES = frozenset({
    "cp_private.pem", "private.pem", "signing_key.pem", "id_rsa", ".env",
    "edge.env", "master_key.hex", "console_token.txt",
})
# A secret VALUE being assigned, not the variable being mentioned. The annex and
# this script both name ATL_MASTER_KEY_HEX on purpose.
FORBIDDEN_ASSIGNMENTS = ("ATL_MASTER_KEY_HEX=", "ATL_CONSOLE_TOKEN=")
FORBIDDEN_CONTENT = ("BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY")


def sha256_file(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def audit_bundle(bundle: pathlib.Path) -> list[str]:
    """Return a list of problems. Empty list means the bundle is shippable."""
    problems: list[str] = []
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle)
        if path.name in FORBIDDEN_NAMES:
            problems.append(f"forbidden file in bundle: {rel}")
        if path.suffix in (".pyc", ".so") or path.stat().st_size > 8_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for marker in FORBIDDEN_CONTENT:
            if marker in text:
                problems.append(f"{rel} contains {marker!r}")
        for marker in FORBIDDEN_ASSIGNMENTS:
            for line in text.splitlines():
                stripped = line.strip().lstrip("export ").strip()
                if not stripped.startswith(marker):
                    continue
                value = stripped[len(marker):].strip().strip('"\'')
                # An empty assignment, or one reading from the environment, is
                # configuration. A literal is a leaked secret.
                if value and not value.startswith("$") and "os.environ" not in value:
                    problems.append(f"{rel} assigns a literal to {marker}{'*' * 6}")
    return problems


def build(args: argparse.Namespace) -> int:
    out = pathlib.Path(args.out).resolve()
    bundle = out / args.node_id
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True)

    # ---- the stack
    for rel in BUNDLE_FILES:
        src = ROOT / rel
        if not src.exists():
            print(f"  missing, skipped: {rel}")
            continue
        dst = bundle / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    for rel in BUNDLE_DIRS:
        src = ROOT / rel
        if not src.exists():
            continue
        shutil.copytree(src, bundle / rel,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".cache",
                                                      "*.env", "*_token.txt",
                                                      # The packager itself does not
                                                      # travel: the buyer has no
                                                      # signing key and no reason to
                                                      # mint licences. It also holds
                                                      # the private-key markers the
                                                      # audit looks for, so shipping
                                                      # it would trip its own guard.
                                                      "package_node.py",
                                                      "push_to_github.sh"))
    for pattern in BUNDLE_GLOBS:
        for src in ROOT.glob(pattern):
            dst = bundle / src.relative_to(ROOT)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    # ---- the control-plane signing key (kept OUT of the bundle)
    if args.signing_key:
        key_path = pathlib.Path(args.signing_key).resolve()
        from cryptography.hazmat.primitives import serialization
        private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        signer = EntitlementSigner(private)
        print(f"  signing with existing control-plane key: {key_path}")
    else:
        signer = EntitlementSigner.generate()
        key_path = out / "cp_private.pem"
        from cryptography.hazmat.primitives import serialization
        key_path.write_bytes(signer.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        os.chmod(key_path, 0o600)
        print(f"  generated control-plane key OUTSIDE the bundle: {key_path}")
        print("  keep it; it signs licences. It is not in the bundle by design.")

    # ---- the node licence
    now = time.time()
    ent = Entitlement(
        license_id=args.license_id or f"lic-{args.node_id}",
        organization_id=args.org_id,
        plan=args.plan,
        issued_at=now - 60,
        expires_at=now + args.days * 86400,
        max_nodes=1,
        capabilities=("agent_access",),
        node_id=args.node_id,          # bound. An empty value here would make
                                       # the licence valid on every node.
    )
    signed = signer.sign(ent)
    (bundle / "licence").mkdir()
    (bundle / "licence" / "entitlement.json").write_text(
        json.dumps({"payload": signed.payload, "signature": signed.signature}, indent=2))
    (bundle / "licence" / "cp_public.pem").write_bytes(signer.public_key_pem())

    # Prove the licence we just wrote is actually node-bound before shipping it.
    verify_entitlement(signed, signer.public_key_pem(), node_id=args.node_id)
    moved = False
    try:
        verify_entitlement(signed, signer.public_key_pem(), node_id=args.node_id + "-other")
        moved = True
    except ValueError:
        pass
    if moved:
        print("  REFUSING to ship: the licence verifies on another node")
        return 1

    # ---- env file
    (bundle / "node.env").write_text(
        "# ATL Edge node configuration. Source this before start_stack.sh.\n"
        "#\n"
        "# ATL_MASTER_KEY_HEX is NOT here. start_stack.sh provisions a node key\n"
        "# on first run; the master key stays with whoever provisions, and a\n"
        "# connector opens packages with the derived node key only.\n"
        f"export ATL_NODE_ID={args.node_id}\n"
        f"export ATL_ORG_ID={args.org_id}\n"
        f"export ATL_CATALOG={args.catalog}\n"
        "export ATL_ENTITLEMENT_PATH=./licence/entitlement.json\n"
        "export ATL_CONTROL_PLANE_PUBLIC_KEY_PATH=./licence/cp_public.pem\n"
        "export ATL_PACKAGE_KEY_ID=edge-v1\n"
        "# Loopback only. Exposing the console needs your own TLS proxy.\n"
        "export ATL_EDGE_BIND=127.0.0.1\n"
    )

    # ---- manifest
    files = sorted(p for p in bundle.rglob("*") if p.is_file())
    manifest = {
        "node_id": args.node_id,
        "organization_id": args.org_id,
        "catalog": args.catalog,
        "plan": args.plan,
        "licence": {
            "license_id": ent.license_id,
            "expires_at": ent.expires_at,
            "expires_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ent.expires_at)),
            "max_nodes": 1,
            "bound_to_node": True,
            "verified_refused_on_other_node": True,
        },
        "excluded_by_design": [
            "control-plane private key (would let the holder mint licences)",
            "ATL_MASTER_KEY_HEX (provisions node keys; the node needs only its own)",
        ],
        "file_count": len(files),
        "files": {str(p.relative_to(bundle)): sha256_file(p) for p in files},
    }
    (bundle / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))

    problems = audit_bundle(bundle)
    print(f"\n  bundle: {bundle}")
    print(f"  files:  {len(files)}")
    print(f"  licence: {ent.license_id} bound to {args.node_id}, "
          f"expires {manifest['licence']['expires_at_iso']}")
    if problems:
        print("\n  BUNDLE AUDIT FAILED:")
        for p in problems:
            print(f"    - {p}")
        return 1
    print("  audit: clean (no private key, no master key)")
    print("\n  The buyer runs:")
    print(f"    cd {args.node_id} && source node.env && bash scripts/start_stack.sh")

    if args.smoke_test:
        print("\n  --smoke-test: booting the bundle as the buyer would")
        rc = smoke_test(bundle)
        if rc != 0:
            print("  SMOKE TEST FAILED -- this bundle does not start")
            return rc
        print("  smoke test: the bundle starts and answers /health")
    return 0


def smoke_test(bundle: pathlib.Path) -> int:
    """Boot the bundle in its own directory and require a healthy Edge.

    The only check that catches a missing file, because a manifest cannot.
    """
    import subprocess
    import urllib.request

    script = (
        "set -e\n"
        f"cd {bundle}\n"
        ". ./node.env\n"
        "bash scripts/start_stack.sh\n"
        "sleep 4\n"
        "curl -sf -o /dev/null -w '%{http_code}' http://127.0.0.1:8790/health\n"
        "bash scripts/start_stack.sh --stop >/dev/null 2>&1 || true\n"
    )
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=180)
    body = (proc.stdout or "").strip()
    if proc.returncode != 0 or not body.endswith("200"):
        print(f"    exit={proc.returncode} health={body[-40:]!r}")
        for line in (proc.stderr or "").splitlines()[-8:]:
            print(f"    {line}")
        return 1
    try:
        del urllib.request  # noqa: B018 - only imported to keep intent obvious
    except Exception:  # noqa: BLE001
        pass
    return 0


def verify(path: str) -> int:
    bundle = pathlib.Path(path).resolve()
    man_path = bundle / "MANIFEST.json"
    if not man_path.exists():
        print(f"no MANIFEST.json in {bundle}")
        return 1
    man = json.loads(man_path.read_text())
    bad = [rel for rel, digest in man["files"].items()
           if rel != "MANIFEST.json"
           and (not (bundle / rel).exists() or sha256_file(bundle / rel) != digest)]
    signed = SignedEntitlement.from_json((bundle / "licence" / "entitlement.json").read_text())
    pub = (bundle / "licence" / "cp_public.pem").read_bytes()
    ent = verify_entitlement(signed, pub, node_id=man["node_id"])
    portable = True
    try:
        verify_entitlement(signed, pub, node_id=man["node_id"] + "-other")
    except ValueError:
        portable = False
    problems = audit_bundle(bundle)

    print(f"  node_id ............. {man['node_id']}")
    print(f"  licence ............. {ent.license_id} (expires {man['licence']['expires_at_iso']})")
    print(f"  node-bound .......... {'yes' if not portable else 'NO -- portable!'}")
    print(f"  digest mismatches ... {len(bad)}" + (f" {bad[:4]}" if bad else ""))
    print(f"  audit problems ...... {len(problems)}")
    for p in problems:
        print(f"    - {p}")
    ok = not portable and not bad and not problems
    print(f"\n  BUNDLE: {'OK' if ok else 'BROKEN'}")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", metavar="BUNDLE_DIR")
    ap.add_argument("--node-id")
    ap.add_argument("--org-id", default="org-pilot")
    ap.add_argument("--license-id", default="")
    ap.add_argument("--plan", default="edge")
    ap.add_argument("--catalog", default="inventory", choices=("crm", "inventory"))
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--signing-key", default="")
    ap.add_argument("--out", default="dist")
    ap.add_argument("--smoke-test", action="store_true",
                    help="after building, BOOT the bundle and require /health")
    args = ap.parse_args(argv)

    if args.verify:
        return verify(args.verify)
    if not args.node_id:
        ap.error("--node-id is required (or use --verify)")
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
