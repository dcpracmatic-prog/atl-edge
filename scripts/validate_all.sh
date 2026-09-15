#!/usr/bin/env bash
# One-shot validation for due diligence / data room.
# Host path always runs. Docker path runs when docker is available.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}/vendor:${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

echo "============================================================"
echo "ATL Edge + SmartTokenProd — validation"
echo "============================================================"

echo ""
echo "==> [1/5] Python dependencies"
python3 -m pip install -q -r requirements.txt \
  --index-url https://pypi.org/simple \
  --trusted-host pypi.org --trusted-host files.pythonhosted.org

echo ""
echo "==> [2/5] Native build"
bash build.sh

echo ""
echo "==> [3/5] Adversarial battery (--require-full)"
python3 testbench/run_testbench.py --require-full --json testbench/last_report.json

echo ""
echo "==> [4/5] Performance dossier"
python3 testbench/perf_dossier.py --out testbench/perf_report.md --json testbench/perf_report.json

echo ""
echo "==> [5/6] Long-lived self-test"
python3 examples/long_lived_protection_selftest.py

echo ""
echo "==> [6/6] Red-Team bypass v1"
python3 testbench/redteam_bypass_v1.py --require-clean

echo ""
if command -v docker >/dev/null 2>&1; then
  echo "==> Docker path"
  docker compose build
  docker compose run --rm testbench
  docker compose run --rm bench
  echo "Docker validation: OK"
else
  echo "==> Docker not available in this environment — skipped"
  echo "    Buyer/CI with Docker should run:"
  echo "      docker compose up --build -d"
  echo "      docker compose run --rm testbench"
  echo "      docker compose run --rm bench"
fi

echo ""
echo "============================================================"
echo "HOST VALIDATION COMPLETE"
echo "  testbench/last_report.json"
echo "  testbench/perf_report.md"
echo "============================================================"
