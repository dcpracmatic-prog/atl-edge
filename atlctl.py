#!/usr/bin/env python3
"""ATL Edge control CLI: activation, status and Connector provisioning."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from src.licensing import activation_fingerprint, generate_api_key, verify_entitlement, SignedEntitlement, NodeIdentity, write_node_identity
from src.sdk_provisioner import provision_bundle


def main() -> int:
    ap = argparse.ArgumentParser(prog="atlctl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate-api-key", help="development-only key generator")

    rl = sub.add_parser("request-license", help="exchange an API key for a signed entitlement over HTTP(S)")
    rl.add_argument("--control-plane-url", required=True, help="e.g. https://control-plane.internal")
    rl.add_argument("--key", required=True)
    rl.add_argument("--node-id", required=True)
    rl.add_argument("--instance-id", required=True)
    rl.add_argument("--agent-id", required=True)
    rl.add_argument("--entitlement-out", type=Path, default=Path(".atl/entitlement.json"))
    rl.add_argument("--public-key-out", type=Path, default=Path(".atl/control-plane-public-key.pem"))
    rl.add_argument("--ca-cert", type=Path, default=None,
                     help="trust this CA (or, in dev, this specific self-signed cert) for https:// URLs")
    rl.add_argument("--insecure-dev-tls", action="store_true",
                     help="DEV ONLY: skip TLS certificate verification entirely. Refuses to run unless "
                          "ATL_ALLOW_INSECURE_TLS=1 is also set in the environment.")

    act = sub.add_parser("activate")
    act.add_argument("--key", required=True)
    act.add_argument("--entitlement", type=Path, required=True)
    act.add_argument("--public-key", type=Path, required=True)
    act.add_argument("--state", type=Path, default=Path(".atl/state"))
    st = sub.add_parser("status")
    st.add_argument("--state", type=Path, default=Path(".atl/state"))
    pb = sub.add_parser("provision-connector")
    pb.add_argument("--manifest", type=Path, required=True)
    pb.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    if args.cmd == "generate-api-key":
        print(generate_api_key("atl_test"))
        return 0
    if args.cmd == "request-license":
        ssl_ctx = None
        if args.control_plane_url.startswith("https://"):
            from src.dev_tls import client_context
            if args.insecure_dev_tls:
                if os.environ.get("ATL_ALLOW_INSECURE_TLS") != "1":
                    print(
                        "--insecure-dev-tls requires ATL_ALLOW_INSECURE_TLS=1 in the environment "
                        "as a second, explicit acknowledgement", file=sys.stderr,
                    )
                    return 2
                ssl_ctx = client_context(insecure_skip_verify=True, allow_insecure=True)
            elif args.ca_cert:
                ssl_ctx = client_context(ca_path=args.ca_cert)
            # else: system default verification, which is correct against a
            # real production certificate.
        open_kwargs = {"timeout": 10}
        if ssl_ctx is not None:
            open_kwargs["context"] = ssl_ctx
        pub_req = urllib.request.Request(args.control_plane_url.rstrip("/") + "/v1/public-key", method="GET")
        try:
            with urllib.request.urlopen(pub_req, **open_kwargs) as resp:
                pub = json.loads(resp.read().decode("utf-8"))["public_key_pem"]
        except urllib.error.URLError as exc:
            print(f"could not reach control plane: {exc}", file=sys.stderr)
            return 2
        body = json.dumps({
            "api_key": args.key, "node_id": args.node_id,
            "instance_id": args.instance_id, "agent_id": args.agent_id,
        }).encode("utf-8")
        act_req = urllib.request.Request(
            args.control_plane_url.rstrip("/") + "/v1/activate", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(act_req, **open_kwargs) as resp:
                signed_obj = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            print(f"activation rejected: HTTP {exc.code}", file=sys.stderr)
            return 2
        args.entitlement_out.parent.mkdir(parents=True, exist_ok=True)
        args.entitlement_out.write_text(json.dumps(signed_obj, indent=2, sort_keys=True) + "\n")
        args.public_key_out.parent.mkdir(parents=True, exist_ok=True)
        args.public_key_out.write_text(pub)
        print(json.dumps({
            "status": "ENTITLEMENT_RECEIVED",
            "entitlement": str(args.entitlement_out),
            "public_key": str(args.public_key_out),
        }, indent=2))
        return 0
    if args.cmd == "activate":
        signed = SignedEntitlement.from_json(args.entitlement.read_text())
        # The key itself is never persisted. In production this validation is
        # preceded by the control-plane exchange keyed by the supplied API key.
        expected_fp = signed.payload.get("activation_key_fingerprint")
        if expected_fp and expected_fp != activation_fingerprint(args.key):
            print("activation rejected", file=sys.stderr)
            return 2
        ent = verify_entitlement(signed, args.public_key.read_bytes())
        args.state.mkdir(parents=True, exist_ok=True)
        (args.state / "entitlement.json").write_text(signed.to_json() + "\n")
        print(json.dumps({"status": "ACTIVE", "license_id": ent.license_id, "plan": ent.plan, "expires_at": ent.expires_at}, indent=2))
        return 0
    if args.cmd == "status":
        p = args.state / "entitlement.json"
        if not p.exists():
            print(json.dumps({"status": "LOCKED"}, indent=2))
            return 0
        print(json.dumps({"status": "ENTITLEMENT_PRESENT", "path": str(p)}, indent=2))
        return 0
    if args.cmd == "provision-connector":
        manifest = json.loads(args.manifest.read_text())
        out = provision_bundle(manifest, args.output)
        print(json.dumps({"status": "READY", "connector_bundle": str(out)}, indent=2))
        return 0
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
