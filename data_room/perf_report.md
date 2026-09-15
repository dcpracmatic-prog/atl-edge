# SmartTokenProd — Performance Dossier

Generated: `2026-09-15T02:23:45Z`  
Version: `0.4.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 40604 |
| RSS after (KB) | 42556 |
| Dossier runtime (s) | 0.101 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 1.469 | 1.371 | 1.631 | 2.818 |
| open (legitimate) | 1.147 | 1.109 | 1.379 | 1.512 |
| open (forced failure + friction) | 1.867 | 1.848 | 2.083 | 2.093 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 19.56 |
| Mean task (ms) | 6.526 |
| Max task (ms) | 12.39 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see \`vendor/smart_token_prod/persistence.py\`); file-local MAC-authenticated
  snapshots do not coordinate across processes.
