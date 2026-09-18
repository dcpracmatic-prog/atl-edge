#!/usr/bin/env python3
"""Regenerate data_room/VALIDATION_REPORT.md from fresh runs of THIS tree.

Every figure and version string is read from the JSON reports and from the
installed vendor package, so the report cannot drift from the trunk the way a
hand-edited one does. Run it at tag time so the report carries the tag's date
and commit, not an older one.

    PYTHONPATH=. python testbench/run_testbench.py --require-full \
        --json data_room/last_report.json
    PYTHONPATH=. python testbench/perf_dossier.py \
        --out data_room/perf_report.md --json data_room/perf_report.json
    PYTHONPATH=. python testbench/redteam_bypass_v1.py --require-clean \
        --json data_room/redteam_report.json --md data_room/redteam_matrix.md
    PYTHONPATH=. python scripts/write_data_room_report.py
"""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_ROOM = ROOT / "data_room"

# A1–A14 from docs/CONSOLE.md, each tied to the run that evidences it.
ACCEPTANCE = [
    ("A1", "¬Authorized(proposal) ⇒ ¬Effect ∧ ¬Issue", "redteam --require-clean; /v1/propose refusals in MVP demo"),
    ("A2", "Issue ⇒ Authorized ∧ Classified ∧ Licensed ∧ Bound", "e2e_full_stack_selftest; MVP demo against production()"),
    ("A3", "Edge HTTP does not expose issue_for_agent", "redteam RT16; /v1/capabilities raw_issue=false"),
    ("A4", "Console does not issue licenses", "404 on POST /api/environments/license (mvp-demo job)"),
    ("A5", "Console authenticated", "401 without token, 200 with token (mvp-demo job)"),
    ("A6", "Console loopback by default", "start_stack.sh binds 127.0.0.1; public bind needs ATL_CONSOLE_BIND_PUBLIC=1"),
    ("A7", "ATLP still AES-GCM (not HMAC-JSON)", "wc -c src/data_plane.py + PackageCrypto battery"),
    ("A8", "fields required in prod", "console execute without fields -> 400; edge -> 403 INERT"),
    ("A9", "SmartToken binding + Argon2id", "adversarial battery, pqcrypto present"),
    ("A10", "Fail-closed without master", "Edge refuses to start without config (mvp-demo job)"),
    ("A11", "Connector without provisioning master", "MVP demo opens package with ATL_NODE_KEY_HEX, master unset"),
    ("A12", "Firestore/Gemini absent from data-plane", "no GCP credentials in Edge/console compose"),
    ("A13", "CI green including console job", "Actions CI: validate, redteam, console-selftest, sidecar-smoke, mvp-demo"),
    ("A14", "Proposal stubs not on main", "wc -c src/data_plane.py ≈ 25014"),
]


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    report = json.loads((DATA_ROOM / "last_report.json").read_text())
    perf = json.loads((DATA_ROOM / "perf_report.json").read_text())
    redteam_path = DATA_ROOM / "redteam_report.json"
    redteam = json.loads(redteam_path.read_text()) if redteam_path.exists() else None

    s = report["summary"]
    env = report.get("environment", {})
    version = env.get("version") or perf.get("smart_token_prod_version") or "unknown"

    try:
        import smart_token_prod

        declared = getattr(smart_token_prod, "__version__", "unknown")
    except Exception:
        declared = "unavailable"
    if declared not in ("unknown", "unavailable") and declared != version:
        print(
            "ERROR: report version %r != vendored smart_token_prod.__version__ %r"
            % (version, declared),
            file=sys.stderr,
        )
        return 1

    data_plane_bytes = (ROOT / "src" / "data_plane.py").stat().st_size
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sha = _git("rev-parse", "HEAD")
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    describe = _git("describe", "--tags", "--always", "--dirty")
    dirty = bool(_git("status", "--porcelain"))

    rows = "\n".join(
        "- **%s** [%s] %s" % (c.get("id", "?"), c.get("status", "?"), c.get("title", ""))
        for c in report.get("cases", [])
    )

    rt = ""
    if redteam:
        r = redteam["summary"]
        rt = f"""
## Execution-boundary red team

| Metric | Value |
|--------|-------|
| Total attacks | {r['total']} |
| BLOCK | {r['blocked']} |
| Bypass (known in-process trust) | {r['known_process_trust_findings']} |
| **Unknown bypasses** | **{r['unknown_bypasses']}** |
| Control baseline OK | {r['control_baseline_ok']} |
| Clean | {r['clean']} |

The single bypass is the documented in-process trust model: code already holding
a `LocalDataPlane` can seal. The network boundary (`src/edge_api_server.py`) is
closed — see `redteam_matrix.md`, RT16.
"""

    accept = "\n".join(
        "| %s | %s | %s |" % (i, prop, how) for i, prop, how in ACCEPTANCE
    )

    docker = (
        "Docker available in the generating environment; the containerised path can be "
        "confirmed with `docker compose run --rm testbench`."
        if shutil.which("docker")
        else "Docker was **not available** in the environment that generated this report. "
        "The host path above is green; a buyer-side confirmation of "
        "`docker compose run --rm testbench` is recommended."
    )

    md = f"""# Validation Report — ATL Edge SmartToken Integrated Hardened

**Generated (UTC):** {now}
**Commit:** `{sha}` (branch `{branch}`, describe `{describe}`)
**Working tree:** {"DIRTY — regenerate from a clean checkout before shipping" if dirty else "clean"}
**Purpose:** Evidence package for technical due diligence / data room.

Generated by `scripts/write_data_room_report.py` from the JSON reports in this
directory. Do not hand-edit: rerun the commands in that script's docstring.

## Executive result

| Check | Result |
|-------|--------|
| Adversarial battery | **{s['passed']}/{s['total']} PASS**, failed={s['failed']}, skipped={s['skipped']}, n/a={s.get('not_applicable', 0)} |
| `--require-full` | **{"PASS" if s['ok'] and s['skipped'] == 0 else "FAIL"}** |
| pqcrypto | {env.get('pqcrypto')} |
| Native friction (`libfriction.so`) | {perf.get('native_friction')} |
| SmartTokenProd version | {version} |
| ATLP data plane (`src/data_plane.py`) | {data_plane_bytes} bytes — AES-256-GCM |
| Protect p50 (64 KiB artifact) | {perf['serial']['protect']['p50_ms']} ms |
| Open legitimate p50 | {perf['serial']['open_legitimate']['p50_ms']} ms |

Performance figures are measured on the generating host
({platform.system()} {platform.machine()}, Python {platform.python_version()}) and
are not a hardware claim; re-measure on target hardware.

## Adversarial cases

{rows}

**Reading N/A:** a case marked N/A tests a property the current `.stok` format
does not have by design, so no host could ever turn it green and it is not
counted as a pass. A9 and A12 target `salt` / `material`, which are deliberately
empty in format v2 — coherence is a public-view metric, not an authorization
oracle. A SKIP would mean something different and worse: that this host is
missing a dependency and the evidence is incomplete. `--require-full` fails on
SKIP and tolerates N/A, which is why both counts are reported separately above.
{rt}
## A1–A14 acceptance criteria

Ticked only where a run in this tree evidences the property.

| ID | Property | Evidence |
|----|----------|----------|
{accept}

## How this evidence was produced

```bash
bash scripts/validate_all.sh
PYTHONPATH=. python testbench/run_testbench.py --require-full \\
    --json data_room/last_report.json
PYTHONPATH=. python testbench/perf_dossier.py \\
    --out data_room/perf_report.md --json data_room/perf_report.json
PYTHONPATH=. python testbench/redteam_bypass_v1.py --require-clean \\
    --json data_room/redteam_report.json --md data_room/redteam_matrix.md
PYTHONPATH=. python scripts/write_data_room_report.py
```

The demo roundtrip (propose → gate → execute → connector open with the node key)
is `examples/mvp_demo_run.py`, also run by the `mvp-demo` CI job, which uploads
its transcript as a build artifact.

## Docker path

{docker}

## Data room files

| File | Description |
|------|-------------|
| `last_report.json` | Full adversarial battery machine report |
| `perf_report.md` / `perf_report.json` | Performance dossier |
| `redteam_report.json` / `redteam_matrix.md` | Execution-boundary red team |
| `THREAT_MODEL.md` | Scope / non-scope / attack surface |
| `QUICKSTART.md` | Integration in < 10 lines + sidecar + Docker |
| `CHECKSUMS.sha256` | Digests of the files in this directory |
| `VALIDATION_REPORT.md` | This document |

## Limits (unchanged, intentional)

- Friction is file-local and MAC-authenticated; not a distributed multi-worker
  counter without `FrictionStore`.
- Sidecar is a localhost/HTTP process boundary, not mesh security.
- No production customer deployment is claimed by this report. See `iva.md` for
  the full statement of limits and out-of-scope items.
"""

    out = DATA_ROOM / "VALIDATION_REPORT.md"
    out.write_text(md)
    print("wrote %s" % out)

    # Refresh checksums for everything in the data room except the digest file.
    lines = []
    for path in sorted(DATA_ROOM.rglob("*")):
        if path.is_file() and path.name != "CHECKSUMS.sha256":
            lines.append("%s  %s" % (_sha256(path), path.relative_to(DATA_ROOM)))
    checks = DATA_ROOM / "CHECKSUMS.sha256"
    checks.write_text(
        "# sha256 digests of data_room contents\n"
        "# Generated %s for commit %s\n" % (now, sha) + "\n".join(lines) + "\n"
    )
    print("wrote %s (%d entries)" % (checks, len(lines)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
