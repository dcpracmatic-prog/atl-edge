from pathlib import Path
import json
import tempfile
import time

from src.licensing import Entitlement, EntitlementSigner, SignedEntitlement, activation_fingerprint, generate_api_key, verify_entitlement, NodeIdentity, write_node_identity
from src.sdk_provisioner import provision_bundle


def main():
    key = generate_api_key("atl_test")
    signer = EntitlementSigner.generate()
    now = time.time()
    ent = Entitlement(
        license_id="lic-test-001", organization_id="acme", plan="enterprise",
        issued_at=now - 1, expires_at=now + 86400,
        max_nodes=10, max_agents=25, capabilities=("agent_access", "predigest", "classification"),
        node_id="node-01", instance_id="instance-01", key_id="node-key-01",
    )
    signed = signer.sign(ent)
    assert verify_entitlement(signed, signer.public_key_pem(), organization_id="acme", node_id="node-01").license_id == ent.license_id
    bad = dict(signed.payload)
    bad["plan"] = "free"
    try:
        verify_entitlement(SignedEntitlement(bad, signed.signature), signer.public_key_pem())
        raise AssertionError("tampered entitlement accepted")
    except ValueError:
        pass
    assert len(activation_fingerprint(key)) == 16

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        identity = NodeIdentity.generate("acme", "node-01", "instance-01", "agent-01")
        write_node_identity(identity, root / "node")
        manifest = {"organization_id":"acme","instance_id":"instance-01","node_id":"node-01","agent_id":"agent-01","policies":["default"],"skills":["lookup"]}
        out = provision_bundle(manifest, root / "connector")
        assert (out / "connector-config.json").exists()
        assert (out / "atl_sdk.py").exists()
        assert not (out / "node-key.hex").exists()
    print("licensing selftest: PASS")

if __name__ == "__main__":
    main()
