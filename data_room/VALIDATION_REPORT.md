# Validation Report — ATL Edge SmartToken Integrated Hardened v2

**Generated (UTC):** 2026-09-15T02:24:48Z  
**Purpose:** Evidence package for technical due diligence / data room.

## Executive result

| Check | Result |
|-------|--------|
| Adversarial battery | **14/14 PASS**, failed=0, skipped=0 |
| `--require-full` | **PASS** |
| pqcrypto | True |
| Native friction (`libfriction.so`) | True |
| SmartTokenProd version | 0.4.4 |
| Protect p50 (64 KiB artifact) | 1.371 ms |
| Open legitimate p50 | 1.109 ms |
| Concurrent failed-open wall (8 workers × 2) | 19.56 ms |

## Adversarial cases

- **A1** [PASS] Key binding: ss alone cannot decrypt (property)
- **A6** [PASS] Low-level bypass model (unbound vs bound)
- **A2** [PASS] .stok does not embed sk
- **A3** [PASS] Wrong master_secret fails + friction
- **A4** [PASS] Missing sk fails + friction
- **A5** [PASS] Ciphertext tampering fails closed
- **A7** [PASS] Friction persistence across opens
- **A8** [PASS] Legitimate round-trip
- **A9** [PASS] Coherence/material mismatch fails closed
- **A10** [PASS] Tampered friction_snapshot fails header MAC
- **A11** [PASS] Tampered public_label fails header MAC
- **A12** [PASS] Tampered salt fails header MAC
- **A15** [PASS] Mixed .stok A + key B fails closed
- **A17** [PASS] Truncated .stok fails closed


## How this evidence was produced

```bash
bash scripts/validate_all.sh
```

Equivalent manual steps:

```bash
pip install -r requirements.txt --index-url https://pypi.org/simple
bash build.sh
PYTHONPATH=vendor:. python testbench/run_testbench.py --require-full --json testbench/last_report.json
PYTHONPATH=vendor:. python testbench/perf_dossier.py --out testbench/perf_report.md --json testbench/perf_report.json
PYTHONPATH=vendor:. python examples/long_lived_protection_selftest.py
```

## Docker path

Docker was **not available** in the environment that generated this report (`docker: command not found`).  
The repository includes a reproducible path for any host with Docker:

```bash
docker compose up --build -d
docker compose run --rm testbench   # must exit 0, 14/14
docker compose run --rm bench       # writes performance dossier inside container
```

A buyer-side confirmation of the Docker path is recommended before closing; the host path above is already green.

## Data room files

| File | Description |
|------|-------------|
| `last_report.json` | Full adversarial battery machine report |
| `perf_report.md` | Human-readable performance dossier |
| `perf_report.json` | Machine-readable performance metrics |
| `THREAT_MODEL.md` | Scope / non-scope / attack surface |
| `QUICKSTART.md` | Integration in < 10 lines + sidecar + Docker |
| `VALIDATION_REPORT.md` | This document |

## Limits (unchanged, intentional)

- Friction is file-local and MAC-authenticated; not a distributed multi-worker counter without `FrictionStore`.
- Sidecar is localhost/HTTP process boundary, not mesh security.
- No production customer PoC is claimed by this report.
