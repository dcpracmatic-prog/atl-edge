#!/usr/bin/env bash
# Deploy ATL Edge API end-to-end: license tokens (if needed) + start server.
#
# Usage:
#   bash scripts/deploy_edge.sh                  # host process, bootstrap if no edge.env
#   bash scripts/deploy_edge.sh --docker         # docker compose edge-api
#   bash scripts/deploy_edge.sh --bootstrap-only # only generate .atl/edge/*
#   bash scripts/deploy_edge.sh --status
#
# Full client stack (Edge + Operator console URL):
#   bash scripts/start_stack.sh                  # → http://127.0.0.1:8795/
#   bash scripts/start_stack.sh --docker
#
# Env overrides:
#   ATL_EDGE_DIR, ATL_CP_STATE, ATL_ORG, ATL_NODE_ID, ATL_AGENT_ID, ATL_HOST, ATL_PORT
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

EDGE_DIR="${ATL_EDGE_DIR:-$ROOT/.atl/edge}"
CP_STATE="${ATL_CP_STATE:-$ROOT/.atl/control-plane}"
ORG="${ATL_ORG:-demo-org}"
NODE_ID="${ATL_NODE_ID:-edge-node-1}"
INSTANCE_ID="${ATL_INSTANCE_ID:-instance-1}"
AGENT_ID="${ATL_AGENT_ID:-agent-1}"
HOST="${ATL_HOST:-127.0.0.1}"
PORT="${ATL_PORT:-8790}"
MODE="host"
BOOTSTRAP_ONLY=0
STATUS_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --docker) MODE="docker" ;;
    --bootstrap-only) BOOTSTRAP_ONLY=1 ;;
    --status) STATUS_ONLY=1 ;;
    --help|-h)
      sed -n '2,18p' "$0"
      exit 0
      ;;
  esac
done

ENV_FILE="$EDGE_DIR/edge.env"

log() { printf '[deploy-edge] %s\n' "$*"; }

ensure_bootstrap() {
  if [[ -f "$ENV_FILE" ]]; then
    log "using existing $ENV_FILE"
    return 0
  fi
  log "no edge.env — running atlctl bootstrap-edge"
  mkdir -p "$EDGE_DIR" "$CP_STATE"
  python3 "$ROOT/atlctl.py" bootstrap-edge \
    --state "$CP_STATE" \
    --out-dir "$EDGE_DIR" \
    --org "$ORG" \
    --plan enterprise \
    --node-id "$NODE_ID" \
    --instance-id "$INSTANCE_ID" \
    --agent-id "$AGENT_ID" \
    --save-api-key
  log "wrote $ENV_FILE"
}

status_edge() {
  if [[ ! -f "$ENV_FILE" ]]; then
    log "not deployed (missing $ENV_FILE)"
    return 1
  fi
  # shellcheck disable=SC1090
  set -a && source "$ENV_FILE" && set +a
  log "node=${ATL_NODE_ID:-?} license=${ATL_LICENSE_ID:-?} entitlement=${ATL_ENTITLEMENT_PATH:-?}"
  if command -v curl >/dev/null 2>&1; then
    if curl -sf "http://${HOST}:${PORT}/health" >/dev/null 2>&1; then
      log "health: OK http://${HOST}:${PORT}/health"
      curl -s "http://${HOST}:${PORT}/health" || true
      echo
      return 0
    fi
  fi
  log "health: not reachable on ${HOST}:${PORT} (server may be stopped)"
  return 0
}

if [[ "$STATUS_ONLY" -eq 1 ]]; then
  status_edge
  exit $?
fi

ensure_bootstrap

if [[ "$BOOTSTRAP_ONLY" -eq 1 ]]; then
  log "bootstrap-only complete"
  exit 0
fi

if [[ "$MODE" == "docker" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    log "docker not found"
    exit 1
  fi
  log "building and starting edge-api via docker compose"
  # Export env file path for compose
  export ATL_EDGE_ENV_FILE="$ENV_FILE"
  export ATL_EDGE_DIR="$EDGE_DIR"
  docker compose -f "$ROOT/docker-compose.yml" up --build -d edge-api
  sleep 2
  HOST=127.0.0.1 PORT=8790 status_edge || true
  log "logs: docker compose logs -f edge-api"
  exit 0
fi

# Host mode
if [[ ! -d "$ROOT/build" ]] || [[ ! -f "$ROOT/build/libmorph8.so" ]]; then
  log "building natives"
  bash "$ROOT/build.sh"
fi
python3 -m pip install -q -r "$ROOT/requirements.txt" \
  --index-url https://pypi.org/simple \
  --trusted-host pypi.org --trusted-host files.pythonhosted.org 2>/dev/null || true

# shellcheck disable=SC1090
set -a && source "$ENV_FILE" && set +a
log "starting Edge API on ${HOST}:${PORT}"
exec python3 -m src.edge_api_server --host "$HOST" --port "$PORT"
