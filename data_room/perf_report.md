# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T17:59:18Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45280 |
| RSS after (KB) | 557764 |
| Dossier runtime (s) | 8.527 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 119.301 | 118.768 | 122.416 | 132.5 |
| open (legitimate) | 118.033 | 117.761 | 123.084 | 123.487 |
| open (forced failure + friction) | 121.045 | 118.648 | 130.597 | 141.227 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1243.37 |
| Mean task (ms) | 584.328 |
| Max task (ms) | 721.008 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
