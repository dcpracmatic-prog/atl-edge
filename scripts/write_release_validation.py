#!/usr/bin/env python3
"""Write a short VALIDATION_REPORT.md for release packaging."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "VALIDATION_REPORT.md")
    report = json.loads(Path("testbench/last_report.json").read_text())
    perf = json.loads(Path("testbench/perf_report.json").read_text())
    s = report["summary"]
    md = f"""# Validation Report (CI Release)

Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

| Check | Result |
|-------|--------|
| Adversarial | {s["passed"]}/{s["total"]} PASS (failed={s["failed"]}, skipped={s["skipped"]}) |
| require-full | {"PASS" if s["ok"] and s["skipped"] == 0 else "FAIL"} |
| Protect p50 ms | {perf["serial"]["protect"]["p50_ms"]} |
| Open p50 ms | {perf["serial"]["open_legitimate"]["p50_ms"]} |
| Native friction | {perf["native_friction"]} |
"""
    out.write_text(md)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
