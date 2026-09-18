#!/usr/bin/env bash
# One-command client stack: bootstrap → natives → Edge API + Operator console.
#
# Usage:
#   bash scripts/start_stack.sh           # host: Edge :8790 + console :8795
#   bash scripts/start_stack.sh --docker  # compose edge-api + web-console
#   bash scripts/start_stack.sh --stop    # stop host PIDs under .atl/run/
#
# Prints:
#   Operator console: http://127.0.0.1:8795/
#   Edge API (not the app): http://127.0.0.1:8790/health
#
# For Edge-only deploy see scripts/deploy_edge.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}/vendor:${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

EDGE_DIR="${ATL_EDGE_DIR:-$ROOT/.atl/edge}"
DATA_DIR="${ATL_DATA_DIR:-$ROOT/.atl/edge-data}"
RUN_DIR="${ATL_RUN_DIR:-$ROOT/.atl/run}"
ENV_FILE="$EDGE_DIR/edge.env"
EDGE_HOST="${ATL_HOST:-127.0.0.1}"
EDGE_PORT="${ATL_PORT:-8790}"
CONSOLE_HOST="${ATL_CONSOLE_HOST:-127.0.0.1}"
CONSOLE_PORT="${ATL_CONSOLE_PORT:-8795}"
MODE="host"
STOP_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --docker) MODE="docker" ;;
    --stop) STOP_ONLY=1 ;;
    --help|-h)
      sed -n '2,16p' "$0"
      exit 0
      ;;
  esac
done

log() { printf '[start-stack] %s\n' "$*"; }

stop_host() {
  mkdir -p "$RUN_DIR"
  local stopped=0
  for name in edge-api web-console; do
    local pf="$RUN_DIR/${name}.pid"
    if [[ -f "$pf" ]]; then
      local pid
      pid="$(cat "$pf" 2>/dev/null || true)"
      if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
        log "stopping $name pid=$pid"
        kill "$pid" 2>/dev/null || true
        sleep 0.5
        kill -9 "$pid" 2>/dev/null || true
        stopped=1
      fi
      rm -f "$pf"
    fi
  done
  if [[ "$stopped" -eq 0 ]]; then
    log "no host PIDs in $RUN_DIR"
  fi
}

if [[ "$STOP_ONLY" -eq 1 ]]; then
  if [[ "$MODE" == "docker" ]]; then
    log "stopping compose edge-api + web-console"
    docker compose -f "$ROOT/docker-compose.yml" --profile console stop edge-api web-console 2>/dev/null || true
  fi
  stop_host
  exit 0
fi

# --- Bootstrap via deploy_edge if no edge.env ---
if [[ ! -f "$ENV_FILE" ]]; then
  log "no edge.env — bootstrap via deploy_edge.sh --bootstrap-only"
  bash "$ROOT/scripts/deploy_edge.sh" --bootstrap-only
fi

ensure_console_token() {
  if [[ -z "${ATL_CONSOLE_TOKEN:-}" ]]; then
    ATL_CONSOLE_TOKEN="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
    export ATL_CONSOLE_TOKEN
    log "ATL_CONSOLE_TOKEN was unset — generated and set for this session (not echoed)"
  else
    log "ATL_CONSOLE_TOKEN already set"
  fi
}

if [[ "$MODE" == "docker" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    log "docker not found"
    exit 1
  fi
  ensure_console_token
  export ATL_EDGE_ENV_FILE="$ENV_FILE"
  export ATL_EDGE_DIR="$EDGE_DIR"
  export ATL_CONSOLE_TOKEN
  log "bringing up edge-api + web-console (compose profile console)"
  docker compose -f "$ROOT/docker-compose.yml" --profile console up --build -d edge-api web-console
  # Wait for console health
  for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${CONSOLE_PORT}/health" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  echo
  echo "Operator console: http://127.0.0.1:${CONSOLE_PORT}/"
  echo "Edge API (not the app): http://127.0.0.1:${EDGE_PORT}/health"
  echo
  log "logs: docker compose --profile console logs -f edge-api web-console"
  exit 0
fi

# --- Host mode ---
if [[ ! -d "$ROOT/build" ]] || [[ ! -f "$ROOT/build/libmorph8.so" ]]; then
  log "building natives"
  bash "$ROOT/build.sh"
fi
python3 -m pip install -q -r "$ROOT/requirements.txt" \
  --index-url https://pypi.org/simple \
  --trusted-host pypi.org --trusted-host files.pythonhosted.org 2>/dev/null || true

# shellcheck disable=SC1090
set -a && source "$ENV_FILE" && set +a
export ATL_DATA_DIR="$DATA_DIR"
mkdir -p "$DATA_DIR" "$RUN_DIR"
ensure_console_token

stop_host  # clear stale PIDs

log "starting Edge API on ${EDGE_HOST}:${EDGE_PORT}"
nohup python3 -m src.edge_api_server --host "$EDGE_HOST" --port "$EDGE_PORT" \
  >"$RUN_DIR/edge-api.log" 2>&1 &
echo $! >"$RUN_DIR/edge-api.pid"

log "starting Operator console on ${CONSOLE_HOST}:${CONSOLE_PORT}"
nohup python3 -m src.web_console --host "$CONSOLE_HOST" --port "$CONSOLE_PORT" --data-dir "$DATA_DIR" \
  >"$RUN_DIR/web-console.log" 2>&1 &
echo $! >"$RUN_DIR/web-console.pid"

ok=0
for i in $(seq 1 30); do
  if curl -sf "http://${CONSOLE_HOST}:${CONSOLE_PORT}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 1
done
if [[ "$ok" -ne 1 ]]; then
  log "console health not ready — check $RUN_DIR/web-console.log"
  exit 1
fi

echo
echo "Operator console: http://${CONSOLE_HOST}:${CONSOLE_PORT}/"
echo "Edge API (not the app): http://${EDGE_HOST}:${EDGE_PORT}/health"
echo
log "PIDs in $RUN_DIR — stop with: bash scripts/start_stack.sh --stop"
