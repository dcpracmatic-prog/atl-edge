#!/usr/bin/env python3
"""
Quantitative performance dossier for SmartTokenProd / ATL Edge natives.

Produces Markdown (and optional JSON) suitable for due-diligence reviewers:
  - protect / open latency
  - failed-open + friction path cost
  - process RSS before/after
  - concurrent failed opens (tarpit pressure)

Usage:
  python testbench/perf_dossier.py --out testbench/perf_report.md
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

_ROOT = Path(__file__).resolve().parents[1]
for p in (str(_ROOT), str(_ROOT / "vendor")):
    if p not in sys.path:
        sys.path.insert(0, p)


def _rss_kb() -> int:
    # ru_maxrss is KB on Linux
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def _bench_protect_open(iterations: int = 20) -> Dict[str, Any]:
    from smart_token_prod import protect_file, open_stok

    protect_ms: List[float] = []
    open_ok_ms: List[float] = []
    open_fail_ms: List[float] = []

    with tempfile.TemporaryDirectory(prefix="perf-") as tmp:
        tmp_path = Path(tmp)
        payload = os.urandom(64 * 1024)  # 64 KiB artifact
        src = tmp_path / "blob.bin"
        src.write_bytes(payload)
        master = b"perf-master-secret"

        for i in range(iterations):
            out = tmp_path / f"a{i}.stok"
            key = tmp_path / f"a{i}.stok.key"
            t0 = time.perf_counter()
            protect_file(src, output_path=out, key_path=key, master_secret=master,
                         tarpit_seconds=0.05)
            protect_ms.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            pt, info = open_stok(out, master_secret=master, key_path=key, update_friction=False)
            open_ok_ms.append((time.perf_counter() - t0) * 1000)
            assert pt == payload and info.get("recoverable")

            t0 = time.perf_counter()
            pt2, info2 = open_stok(
                out, master_secret=master, key_path=key,
                force_failure=True, update_friction=True,
            )
            open_fail_ms.append((time.perf_counter() - t0) * 1000)
            assert pt2 is None

    def summary(xs: List[float]) -> Dict[str, float]:
        return {
            "n": len(xs),
            "mean_ms": round(statistics.mean(xs), 3),
            "p50_ms": round(statistics.median(xs), 3),
            "p95_ms": round(sorted(xs)[max(0, int(0.95 * len(xs)) - 1)], 3),
            "max_ms": round(max(xs), 3),
        }

    return {
        "artifact_bytes": len(payload),
        "protect": summary(protect_ms),
        "open_legitimate": summary(open_ok_ms),
        "open_forced_failure": summary(open_fail_ms),
    }


def _bench_concurrent_failures(workers: int = 8, per_worker: int = 3) -> Dict[str, Any]:
    """Each task uses its own .stok to avoid concurrent writers on one file.

    Measures aggregate tarpit/friction cost under parallel failed opens.
    """
    from smart_token_prod import protect_file, open_stok

    with tempfile.TemporaryDirectory(prefix="perf-c-") as tmp:
        tmp_path = Path(tmp)
        master = b"perf-master"
        jobs = []
        for i in range(workers * per_worker):
            src = tmp_path / f"blob-{i}.bin"
            src.write_bytes(b"concurrent-perf")
            stok, key = protect_file(
                src, master_secret=master,
                output_path=tmp_path / f"a{i}.stok",
                key_path=tmp_path / f"a{i}.stok.key",
                tarpit_seconds=0.1,
            )
            jobs.append((stok, key))

        latencies: List[float] = []
        lock = threading.Lock()

        def one(pair) -> None:
            stok, key = pair
            t0 = time.perf_counter()
            open_stok(
                stok, master_secret=master, key_path=key,
                force_failure=True, update_friction=True,
            )
            dt = (time.perf_counter() - t0) * 1000
            with lock:
                latencies.append(dt)

        t_wall0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(one, jobs[i]) for i in range(len(jobs))]
            for f in as_completed(futs):
                f.result()
        wall_ms = (time.perf_counter() - t_wall0) * 1000

    return {
        "workers": workers,
        "tasks": workers * per_worker,
        "wall_ms": round(wall_ms, 2),
        "mean_task_ms": round(statistics.mean(latencies), 3) if latencies else None,
        "max_task_ms": round(max(latencies), 3) if latencies else None,
    }


def run(out_md: Path, out_json: Path | None = None) -> Dict[str, Any]:
    from smart_token_prod import __version__
    from smart_token_prod.native import is_available as native_ok

    rss_before = _rss_kb()
    t0 = time.perf_counter()
    serial = _bench_protect_open(iterations=15)
    concurrent = _bench_concurrent_failures(workers=8, per_worker=2)
    elapsed = time.perf_counter() - t0
    rss_after = _rss_kb()

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "smart_token_prod_version": __version__,
        "native_friction": bool(native_ok()),
        "rss_kb_before": rss_before,
        "rss_kb_after": rss_after,
        "dossier_runtime_s": round(elapsed, 3),
        "serial": serial,
        "concurrent_failures": concurrent,
    }

    md = f"""# SmartTokenProd — Performance Dossier

Generated: `{report['generated_at']}`  
Version: `{report['smart_token_prod_version']}`  
Native friction core: **{'yes' if report['native_friction'] else 'no (Python fallback)'}**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | {report['rss_kb_before']} |
| RSS after (KB) | {report['rss_kb_after']} |
| Dossier runtime (s) | {report['dossier_runtime_s']} |

## Serial protect / open (artifact {serial['artifact_bytes']} bytes, n={serial['protect']['n']})

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | {serial['protect']['mean_ms']} | {serial['protect']['p50_ms']} | {serial['protect']['p95_ms']} | {serial['protect']['max_ms']} |
| open (legitimate) | {serial['open_legitimate']['mean_ms']} | {serial['open_legitimate']['p50_ms']} | {serial['open_legitimate']['p95_ms']} | {serial['open_legitimate']['max_ms']} |
| open (forced failure + friction) | {serial['open_forced_failure']['mean_ms']} | {serial['open_forced_failure']['p50_ms']} | {serial['open_forced_failure']['p95_ms']} | {serial['open_forced_failure']['max_ms']} |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | {concurrent['workers']} |
| Tasks | {concurrent['tasks']} |
| Wall clock (ms) | {concurrent['wall_ms']} |
| Mean task (ms) | {concurrent['mean_task_ms']} |
| Max task (ms) | {concurrent['max_task_ms']} |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `vendor/smart_token_prod/persistence.py`); file-local MAC-authenticated
  snapshots do not coordinate across processes.
"""
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(md)
    if out_json:
        out_json.write_text(json.dumps(report, indent=2))
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="testbench/perf_report.md")
    p.add_argument("--json", default="testbench/perf_report.json")
    args = p.parse_args(argv)
    report = run(Path(args.out), Path(args.json) if args.json else None)
    print(f"Wrote {args.out}")
    if args.json:
        print(f"Wrote {args.json}")
    print(json.dumps({"native": report["native_friction"], "serial_protect_p50_ms": report["serial"]["protect"]["p50_ms"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
