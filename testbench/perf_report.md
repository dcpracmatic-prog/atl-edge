# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T20:36:17Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45364 |
| RSS after (KB) | 528992 |
| Dossier runtime (s) | 8.325 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 117.232 | 116.305 | 121.401 | 125.71 |
| open (legitimate) | 114.855 | 113.857 | 116.747 | 127.249 |
| open (forced failure + friction) | 117.159 | 117.618 | 119.511 | 119.629 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1212.04 |
| Mean task (ms) | 560.687 |
| Max task (ms) | 729.401 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
