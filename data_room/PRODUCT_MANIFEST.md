# Product Manifest — Hardened v2

**File:** `atl_edge_smarttoken_integrated_hardened_v2.zip`  
**SHA-256:** `924b113d5acefb60dc90c785a817bc0c2e5c2c4a8cbf86d890f81a390dc6b48d`  
**Size bytes:** 256418

## Must-review paths

| Path | Why |
|------|-----|
| `smart_token_prod/stok.py` (dependencia instalada, tag `v0.10.3`) | friction_mac, AAD recalculado desde `public_label`, open/protect, sk fuera de banda |
| `smart_token_prod/core.py` (idem) | derive_aes_key(ss, master_secret), expected_aad(public_label) |
| `src/long_lived_protection.py` | public API for ATL |
| `src/sidecar_server.py` | HTTP local multi-process boundary |
| `testbench/adversarial_battery.py` | A1–A12, A15, A17 |
| `testbench/last_report.json` | machine evidence 14/14 |
| `testbench/perf_report.md` | lab performance numbers |
| `Dockerfile` / `docker-compose.yml` | reproducible build |
| `scripts/validate_all.sh` | one-shot validation |
| `docs/THREAT_MODEL.md` | scope / non-scope |
| `docs/QUICKSTART.md` | integration |
| `data_room/` | copy of evidence for reviewers |

## Reproduce

```bash
bash scripts/validate_all.sh
# or
docker compose run --rm testbench
```
