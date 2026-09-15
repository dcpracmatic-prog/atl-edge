#!/usr/bin/env python3
"""ATL Connector manifest/status CLI.

The Connector is installed on the external (cloud) agent instance — the
physical/on-prem node runs the Edge instead (`src/data_plane.LocalDataPlane`
+ `src/file_workflow.Outbox`), which is a different piece of software. The
Connector owns the local node identity and configuration, but does not
contain the enterprise database or the provisioning/master key. A
provisioned per-node ATLP key is referenced through ATL_NODE_KEY_HEX at
runtime in this MVP.

This script is the manifest/status surface only: validate the connector's
manifest and report configuration. The actual network runtime that accepts
authenticated pushes from an Edge, decrypts ATLP packages, and hands the
result to the premium agent is `connector/cloud_runtime.ConnectorIngestServer`
(see `src/transport.py` for the authenticated-push side and
`examples/transport_selftest.py` / `examples/e2e_full_stack_selftest.py` for
it running end to end).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict

from src.data_plane import CloudDecryptConnector


REQUIRED = ("organization_id", "instance_id", "node_id", "agent_id")


def load_manifest(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("manifest must be an object")
    missing = [x for x in REQUIRED if not obj.get(x)]
    if missing:
        raise ValueError("missing manifest fields: " + ",".join(missing))
    return obj


def status(manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "organization_id": manifest["organization_id"],
        "instance_id": manifest["instance_id"],
        "node_id": manifest["node_id"],
        "agent_id": manifest["agent_id"],
        "policies": manifest.get("policies", []),
        "skills": manifest.get("skills", []),
        "transport": manifest.get("transport", {"mode": "outbound"}),
        "node_key_provisioned": bool(os.environ.get("ATL_NODE_KEY_HEX")),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="ATL Connector")
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("command", choices=("status",))
    args = ap.parse_args()
    manifest = load_manifest(args.manifest)
    if args.command == "status":
        print(json.dumps(status(manifest), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
