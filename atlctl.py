#!/usr/bin/env python3
"""ATL Edge control CLI: license issuance, activation, Edge env bootstrap, status.

Licensing tokens are produced in two steps:

1. **issue-license** (admin / control plane) — creates a license and prints the
   API key **fingerprint**; raw key goes only to a mode-0600 once-file when requested.
2. **activate-local** or **request-license** — exchanges the API key for a
   signed entitlement bound to node_id + instance_id + agent_id.

**bootstrap-edge** runs both against a local control-plane state directory and
writes ``edge.env`` + ``entitlement.json`` so the Edge API can start without
dev crypto defaults.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from src.licensing import (
    SignedEntitlement,
    activation_fingerprint,
    generate_api_key,
    verify_entitlement,
)
from src.sdk_provisioner import provision_bundle



def _write_api_key_once(path: Path, api_key: str) -> Path:
    """Write one-shot API key to a mode-0600 local file; never print the raw key."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # codeql[py/clear-text-storage-sensitive-data] One-shot local bootstrap artifact (mode 0600); operator retrieves key from this file only.
    path.write_text(api_key + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _cmd_issue_license(args: argparse.Namespace) -> int:
    from src.control_plane import ControlPlane

    state = Path(args.state)
    cp = ControlPlane(state)
    issued = cp.issue_license(
        args.org,
        args.plan,
        duration_days=args.days,
        max_nodes=args.max_nodes,
        max_agents=args.max_agents,
    )
    api_key = issued["api_key"]
    fingerprint = activation_fingerprint(api_key)
    out = {
        "status": "LICENSE_ISSUED",
        "license_id": issued["license_id"],
        "api_key_fingerprint": fingerprint,
        "organization_id": args.org,
        "plan": args.plan,
        "max_nodes": args.max_nodes,
        "max_agents": args.max_agents,
        "duration_days": args.days,
        "control_plane_state": str(state.resolve()),
        "note": "Raw api_key is never printed; use --print-api-key to write api_key.once.txt (0600).",
    }
    key_path = None
    if getattr(args, "print_api_key", False):
        key_path = _write_api_key_once(state / "api_key.once.txt", api_key)
        out["api_key_file"] = str(key_path.resolve())
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        disk = dict(out)
        if args.save_api_key:
            disk["api_key"] = api_key
            # codeql[py/clear-text-storage-sensitive-data] Intentional one-shot license receipt on disk (mode 0600); stdout stays redacted.
            args.json_out.write_text(json.dumps(disk, indent=2) + "\n")
            try:
                os.chmod(args.json_out, 0o600)
            except OSError:
                pass
            if key_path is None:
                # Also materialize once-file when saving key to json-out
                key_path = _write_api_key_once(state / "api_key.once.txt", api_key)
                out["api_key_file"] = str(key_path.resolve())
                disk["api_key_file"] = out["api_key_file"]
                args.json_out.write_text(json.dumps(disk, indent=2) + "\n")
        else:
            args.json_out.write_text(json.dumps(out, indent=2) + "\n")
    # stdout: fingerprint (+ optional file path); never raw api_key
    print(json.dumps(out, indent=2))
    return 0


def _cmd_activate_local(args: argparse.Namespace) -> int:
    from src.control_plane import ControlPlane, LicenseError

    state = Path(args.state)
    cp = ControlPlane(state)
    try:
        signed = cp.activate(
            args.key,
            node_id=args.node_id,
            instance_id=args.instance_id,
            agent_id=args.agent_id,
        )
    except LicenseError as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    args.entitlement_out.parent.mkdir(parents=True, exist_ok=True)
    args.public_key_out.parent.mkdir(parents=True, exist_ok=True)
    # SignedEntitlement may be object with to_json
    if hasattr(signed, "to_json"):
        payload = {"payload": signed.payload, "signature": signed.signature}
        args.entitlement_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        args.entitlement_out.write_text(signed.to_json() + "\n")
    args.public_key_out.write_text(cp.public_key_pem().decode("ascii"))

    ent = verify_entitlement(
        SignedEntitlement(payload=signed.payload, signature=signed.signature),
        cp.public_key_pem(),
        node_id=args.node_id,
    )
    print(
        json.dumps(
            {
                "status": "ACTIVATED",
                "license_id": ent.license_id,
                "node_id": ent.node_id,
                "agent_id": getattr(ent, "agent_id", args.agent_id),
                "expires_at": ent.expires_at,
                "max_nodes": ent.max_nodes,
                "max_agents": ent.max_agents,
                "entitlement": str(args.entitlement_out.resolve()),
                "public_key": str(args.public_key_out.resolve()),
            },
            indent=2,
        )
    )
    return 0


def _write_edge_env(
    path: Path,
    *,
    node_id: str,
    master_hex: str,
    ent,
    entitlement_path: Path,
    public_key_path: Path,
    agent_id: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated by atlctl bootstrap-edge / write-edge-env — do not commit secrets",
        f"ATL_NODE_ID={node_id}",
        f"ATL_MASTER_KEY_HEX={master_hex}",
        f"ATL_LICENSE_ID={ent.license_id}",
        f"ATL_ORG_ID={ent.organization_id}",
        f"ATL_PLAN={ent.plan}",
        f"ATL_AGENT_ID={agent_id}",
        f"ATL_ENTITLEMENT_ISSUED_AT={int(ent.issued_at)}",
        f"ATL_ENTITLEMENT_EXPIRES_AT={int(ent.expires_at)}",
        f"ATL_ENTITLEMENT_PATH={entitlement_path.resolve()}",
        f"ATL_CONTROL_PLANE_PUBLIC_KEY_PATH={public_key_path.resolve()}",
        "# Uncomment only for local demos without real keys:",
        "# ATL_ALLOW_DEV_DEFAULTS=1",
        "",
    ]
    path.write_text("\n".join(lines))


def _cmd_bootstrap_edge(args: argparse.Namespace) -> int:
    """Issue license + activate + write edge.env for a single-node pilot."""
    from src.control_plane import ControlPlane, LicenseError

    state = Path(args.state)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cp = ControlPlane(state)
    issued = cp.issue_license(
        args.org,
        args.plan,
        duration_days=args.days,
        max_nodes=args.max_nodes,
        max_agents=args.max_agents,
    )
    api_key = issued["api_key"]
    fingerprint = activation_fingerprint(api_key)
    try:
        signed = cp.activate(
            api_key,
            node_id=args.node_id,
            instance_id=args.instance_id,
            agent_id=args.agent_id,
        )
    except LicenseError as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    ent_path = out_dir / "entitlement.json"
    pub_path = out_dir / "control-plane-public-key.pem"
    env_path = out_dir / "edge.env"
    key_path = out_dir / "api_key.once.txt"

    payload = {"payload": signed.payload, "signature": signed.signature}
    ent_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    pub_path.write_text(cp.public_key_pem().decode("ascii"))

    api_key_file = None
    if args.save_api_key or args.print_api_key:
        _write_api_key_once(key_path, api_key)
        api_key_file = str(key_path.resolve())

    ent = verify_entitlement(
        SignedEntitlement(payload=signed.payload, signature=signed.signature),
        cp.public_key_pem(),
        node_id=args.node_id,
    )
    master_hex = secrets.token_hex(32)
    _write_edge_env(
        env_path,
        node_id=args.node_id,
        master_hex=master_hex,
        ent=ent,
        entitlement_path=ent_path,
        public_key_path=pub_path,
        agent_id=args.agent_id,
    )
    try:
        os.chmod(env_path, 0o600)
    except OSError:
        pass

    print(
        json.dumps(
            {
                "status": "EDGE_BOOTSTRAP_READY",
                "license_id": issued["license_id"],
                "api_key_fingerprint": fingerprint,
                "node_id": args.node_id,
                "agent_id": args.agent_id,
                "expires_at": ent.expires_at,
                "files": {
                    "entitlement": str(ent_path.resolve()),
                    "public_key": str(pub_path.resolve()),
                    "edge_env": str(env_path.resolve()),
                    "api_key_file": api_key_file,
                    "control_plane_state": str(state.resolve()),
                },
                "start_edge": f"set -a && source {env_path.resolve()} && set +a && PYTHONPATH=. python -m src.edge_api_server --host 127.0.0.1 --port 8790",
                "note": "Raw api_key never printed; retrieve from api_key_file when present (mode 0600).",
            },
            indent=2,
        )
    )
    return 0


def _cmd_write_edge_env(args: argparse.Namespace) -> int:
    """From an existing signed entitlement + public key, write edge.env."""
    signed = SignedEntitlement.from_json(args.entitlement.read_text())
    pub = args.public_key.read_bytes()
    ent = verify_entitlement(signed, pub, node_id=args.node_id or None)
    master_hex = args.master_key_hex or secrets.token_hex(32)
    node_id = args.node_id or ent.node_id or "edge-node-1"
    agent_id = args.agent_id or getattr(ent, "agent_id", "") or ""
    _write_edge_env(
        args.env_out,
        node_id=node_id,
        master_hex=master_hex,
        ent=ent,
        entitlement_path=args.entitlement,
        public_key_path=args.public_key,
        agent_id=agent_id,
    )
    try:
        os.chmod(args.env_out, 0o600)
    except OSError:
        pass
    print(
        json.dumps(
            {
                "status": "EDGE_ENV_WRITTEN",
                "path": str(args.env_out.resolve()),
                "license_id": ent.license_id,
                "expires_at": ent.expires_at,
                "node_id": node_id,
            },
            indent=2,
        )
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="atlctl",
        description="ATL Edge licensing & activation CLI",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # --- licensing tokens ---
    iss = sub.add_parser(
        "issue-license",
        help="Admin: create a license in a local control-plane state dir; print API key once",
    )
    iss.add_argument("--state", type=Path, default=Path(".atl/control-plane"), help="control plane state directory")
    iss.add_argument("--org", required=True, help="organization_id")
    iss.add_argument("--plan", default="enterprise")
    iss.add_argument("--days", type=int, default=365)
    iss.add_argument("--max-nodes", type=int, default=1)
    iss.add_argument("--max-agents", type=int, default=5)
    iss.add_argument("--json-out", type=Path, default=None, help="optional receipt path (api_key redacted unless --save-api-key)")
    iss.add_argument("--save-api-key", action="store_true", help="include api_key in --json-out file on disk (stdout still redacted)")
    iss.add_argument("--print-api-key", action="store_true", help="write <state>/api_key.once.txt (0600); stdout shows path + fingerprint only")

    al = sub.add_parser(
        "activate-local",
        help="Exchange API key for a signed entitlement using local control-plane state",
    )
    al.add_argument("--state", type=Path, default=Path(".atl/control-plane"))
    al.add_argument("--key", required=True, help="API key from issue-license")
    al.add_argument("--node-id", required=True)
    al.add_argument("--instance-id", required=True)
    al.add_argument("--agent-id", required=True)
    al.add_argument("--entitlement-out", type=Path, default=Path(".atl/entitlement.json"))
    al.add_argument("--public-key-out", type=Path, default=Path(".atl/control-plane-public-key.pem"))

    boot = sub.add_parser(
        "bootstrap-edge",
        help="Issue + activate + write edge.env for a single-node pilot (local control plane)",
    )
    boot.add_argument("--state", type=Path, default=Path(".atl/control-plane"))
    boot.add_argument("--out-dir", type=Path, default=Path(".atl/edge"))
    boot.add_argument("--org", default="demo-org")
    boot.add_argument("--plan", default="enterprise")
    boot.add_argument("--days", type=int, default=365)
    boot.add_argument("--max-nodes", type=int, default=1)
    boot.add_argument("--max-agents", type=int, default=5)
    boot.add_argument("--node-id", default="edge-node-1")
    boot.add_argument("--instance-id", default="instance-1")
    boot.add_argument("--agent-id", default="agent-1")
    boot.add_argument("--print-api-key", action="store_true", help="write api_key.once.txt (0600); never print raw key")
    boot.add_argument("--save-api-key", action="store_true", help="write api_key.once.txt under out-dir")

    we = sub.add_parser("write-edge-env", help="Write edge.env from an existing signed entitlement")
    we.add_argument("--entitlement", type=Path, required=True)
    we.add_argument("--public-key", type=Path, required=True)
    we.add_argument("--env-out", type=Path, default=Path(".atl/edge/edge.env"))
    we.add_argument("--node-id", default="")
    we.add_argument("--agent-id", default="")
    we.add_argument("--master-key-hex", default="", help="optional; random 32 bytes if omitted")

    sub.add_parser("generate-api-key", help="development-only random key (not issued by control plane)")

    rl = sub.add_parser("request-license", help="exchange an API key for a signed entitlement over HTTP(S)")
    rl.add_argument("--control-plane-url", required=True, help="e.g. https://control-plane.internal")
    rl.add_argument("--key", required=True)
    rl.add_argument("--node-id", required=True)
    rl.add_argument("--instance-id", required=True)
    rl.add_argument("--agent-id", required=True)
    rl.add_argument("--entitlement-out", type=Path, default=Path(".atl/entitlement.json"))
    rl.add_argument("--public-key-out", type=Path, default=Path(".atl/control-plane-public-key.pem"))
    rl.add_argument("--ca-cert", type=Path, default=None)
    rl.add_argument("--insecure-dev-tls", action="store_true")

    act = sub.add_parser("activate", help="Validate a signed entitlement file into local state")
    act.add_argument("--key", required=True)
    act.add_argument("--entitlement", type=Path, required=True)
    act.add_argument("--public-key", type=Path, required=True)
    act.add_argument("--state", type=Path, default=Path(".atl/state"))

    st = sub.add_parser("status")
    st.add_argument("--state", type=Path, default=Path(".atl/state"))

    cons = sub.add_parser(
        "console",
        help="Start the authenticated operator console (loopback :8795 by default)",
    )
    cons.add_argument("--host", default="127.0.0.1")
    cons.add_argument("--port", type=int, default=8795)
    cons.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("ATL_DATA_DIR", ".atl/edge-data")),
        help="Shared durable data dir (inbox/outbox/ledger); prefer same ATL_DATA_DIR as Edge",
    )

    pb = sub.add_parser("provision-connector")
    pb.add_argument("--manifest", type=Path, required=True)
    pb.add_argument("--output", type=Path, required=True)

    args = ap.parse_args()

    if args.cmd == "issue-license":
        return _cmd_issue_license(args)
    if args.cmd == "activate-local":
        return _cmd_activate_local(args)
    if args.cmd == "bootstrap-edge":
        return _cmd_bootstrap_edge(args)
    if args.cmd == "write-edge-env":
        return _cmd_write_edge_env(args)

    if args.cmd == "generate-api-key":
        key = generate_api_key("atl_test")
        key_path = _write_api_key_once(Path(".atl") / "api_key.once.txt", key)
        print(
            json.dumps(
                {
                    "status": "API_KEY_WRITTEN",
                    "api_key_file": str(key_path.resolve()),
                    "api_key_fingerprint": activation_fingerprint(key),
                    "note": "Raw key written only to api_key_file (mode 0600); not printed.",
                },
                indent=2,
            )
        )
        return 0

    if args.cmd == "request-license":
        ssl_ctx = None
        if args.control_plane_url.startswith("https://"):
            from src.dev_tls import client_context

            if args.insecure_dev_tls:
                if os.environ.get("ATL_ALLOW_INSECURE_TLS") != "1":
                    print(
                        "--insecure-dev-tls requires ATL_ALLOW_INSECURE_TLS=1",
                        file=sys.stderr,
                    )
                    return 2
                ssl_ctx = client_context(insecure_skip_verify=True, allow_insecure=True)
            elif args.ca_cert:
                ssl_ctx = client_context(ca_path=args.ca_cert)
        open_kwargs: dict = {"timeout": 10}
        if ssl_ctx is not None:
            open_kwargs["context"] = ssl_ctx
        pub_req = urllib.request.Request(
            args.control_plane_url.rstrip("/") + "/v1/public-key", method="GET"
        )
        try:
            with urllib.request.urlopen(pub_req, **open_kwargs) as resp:
                pub = json.loads(resp.read().decode("utf-8"))["public_key_pem"]
        except urllib.error.URLError as exc:
            print(f"could not reach control plane: {exc}", file=sys.stderr)
            return 2
        body = json.dumps(
            {
                "api_key": args.key,
                "node_id": args.node_id,
                "instance_id": args.instance_id,
                "agent_id": args.agent_id,
            }
        ).encode("utf-8")
        act_req = urllib.request.Request(
            args.control_plane_url.rstrip("/") + "/v1/activate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
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
        args.public_key_out.write_text(pub if isinstance(pub, str) else pub.decode())
        print(
            json.dumps(
                {
                    "status": "ENTITLEMENT_RECEIVED",
                    "entitlement": str(args.entitlement_out),
                    "public_key": str(args.public_key_out),
                },
                indent=2,
            )
        )
        return 0

    if args.cmd == "activate":
        signed = SignedEntitlement.from_json(args.entitlement.read_text())
        expected_fp = signed.payload.get("activation_key_fingerprint")
        if expected_fp and expected_fp != activation_fingerprint(args.key):
            print("activation rejected", file=sys.stderr)
            return 2
        ent = verify_entitlement(signed, args.public_key.read_bytes())
        args.state.mkdir(parents=True, exist_ok=True)
        (args.state / "entitlement.json").write_text(signed.to_json() + "\n")
        print(
            json.dumps(
                {
                    "status": "ACTIVE",
                    "license_id": ent.license_id,
                    "plan": ent.plan,
                    "expires_at": ent.expires_at,
                },
                indent=2,
            )
        )
        return 0

    if args.cmd == "status":
        p = args.state / "entitlement.json"
        if not p.exists():
            print(json.dumps({"status": "LOCKED"}, indent=2))
            return 0
        print(json.dumps({"status": "ENTITLEMENT_PRESENT", "path": str(p)}, indent=2))
        return 0

    if args.cmd == "console":
        from src.web_console import main as console_main

        return console_main(["--host", args.host, "--port", str(args.port), "--data-dir", str(args.data_dir)])

    if args.cmd == "provision-connector":
        manifest = json.loads(args.manifest.read_text())
        out = provision_bundle(manifest, args.output)
        print(json.dumps({"status": "READY", "connector_bundle": str(out)}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
