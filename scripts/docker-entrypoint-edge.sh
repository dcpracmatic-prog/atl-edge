#!/usr/bin/env bash
# Container entrypoint for Edge API. Expects secrets via env or mounted edge.env.
set -euo pipefail
cd /app
export PYTHONPATH=/app/vendor:/app

if [[ -f /secrets/edge.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source /secrets/edge.env
  set +a
fi

if [[ -z "${ATL_MASTER_KEY_HEX:-}" && "${ATL_ALLOW_DEV_DEFAULTS:-}" != "1" ]]; then
  echo "edge-entrypoint: ATL_MASTER_KEY_HEX missing and ATL_ALLOW_DEV_DEFAULTS not set" >&2
  echo "Mount edge.env at /secrets/edge.env or pass env from deploy_edge.sh --docker" >&2
  exit 1
fi

HOST="${ATL_HOST:-0.0.0.0}"
PORT="${ATL_PORT:-8790}"
exec python -m src.edge_api_server --host "$HOST" --port "$PORT"
