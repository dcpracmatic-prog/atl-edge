#!/usr/bin/env bash
# One-shot validation for due diligence / data room.
# Host path always runs. Docker path runs when docker is available.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

echo "============================================================"
echo "ATL Edge + SmartTokenProd — validation"
echo "============================================================"

echo ""
echo "==> [1/9] Python dependencies"
python3 -m pip install -q -r requirements.txt \
  --index-url https://pypi.org/simple \
  --trusted-host pypi.org --trusted-host files.pythonhosted.org

echo ""
echo "==> [2/9] Native build"
bash build.sh

echo ""
echo "==> [3/9] Adversarial battery (--require-full)"
python3 testbench/run_testbench.py --require-full --json testbench/last_report.json

echo ""
echo "==> [4/9] Performance dossier"
python3 testbench/perf_dossier.py --out testbench/perf_report.md --json testbench/perf_report.json

echo ""
echo "==> [5/9] Long-lived self-test"
python3 examples/long_lived_protection_selftest.py

echo ""
echo "==> [6/9] Red-Team bypass v1"
python3 testbench/redteam_bypass_v1.py --require-clean

echo ""
echo "==> [7/9] MCP connector surface (must stay closed at three tools)"
python3 scripts/check_mcp_surface.py --self-test
python3 src/mcp_server.py --selftest

echo ""
echo "==> [8/9] Proposer vocabulary (cohort widened, permission unchanged)"
python3 testbench/proposer_vocabulary_selftest.py

echo ""
echo "==> [9/9] Inventory trade on real data + governance receipt"
if python3 -c "import sys; sys.path.insert(0,'.'); from src.inventory_catalog import dataset_available; sys.exit(0 if dataset_available() else 1)"; then
  python3 examples/inventory_trade_demo.py --json testbench/inventory_receipt.json
else
  echo "    Dataset not built in this environment — skipped."
  echo "    Build it with: python3 scripts/fetch_inventory_dataset.py"
  echo "    (CI builds it; it is not committed because it is 3rd-party CC BY data.)"
fi

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
