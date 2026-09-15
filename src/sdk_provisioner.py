"""Generate a customer-specific Connector/SDK bundle from an activated node.

The bundle contains identity/configuration and integration code, never the ATL
control-plane private signing key. The per-node secret is provisioned separately
through the local node identity store.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Mapping

SDK_TEMPLATE = '''"""ATL generated connector client."""
import json
from pathlib import Path

class ATLAgentClient:
    def __init__(self, connector_dir=None):
        self.connector_dir = Path(connector_dir or Path(__file__).resolve().parent)
        self.config = json.loads((self.connector_dir / "connector-config.json").read_text())

    def request(self, resource, fields):
        # Transport is intentionally injected by the Connector runtime.
        return {"resource": resource, "fields": list(fields), "status": "QUEUED_TO_CONNECTOR"}
'''


def provision_bundle(manifest: Mapping[str, Any], destination: Path) -> Path:
    required = ("organization_id", "instance_id", "node_id", "agent_id")
    missing = [k for k in required if not manifest.get(k)]
    if missing:
        raise ValueError("missing manifest fields: " + ",".join(missing))
    destination.mkdir(parents=True, exist_ok=True)
    config = dict(manifest)
    config["provisioned_by"] = "atl-edge"
    config["credential_source"] = "node-secret-store"
    config["transport"] = config.get("transport", {"mode": "outbound"})
    (destination / "connector-config.json").write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    (destination / "atl_sdk.py").write_text(SDK_TEMPLATE)
    (destination / "README.txt").write_text(
        "Install this connector bundle on the authorized agent instance.\n"
        "Do not copy node-key.hex into source control or application code.\n"
        "The Connector obtains its per-node secret from the node secret store.\n"
    )
    return destination
