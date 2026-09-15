#!/usr/bin/env bash
# Build all native components used by ATL Edge.
# - morph8 (structural gate)
# - swar_fleet (observation)
# - libfriction.so (SmartTokenProd sequential friction, optional)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
mkdir -p build eo_probe/core

echo "==> Building morph8"
g++ -std=c++17 -O2 -Wall -Wextra -fPIC -shared src/morph8.cpp -o build/libmorph8.so
echo "    build/libmorph8.so"

echo "==> Building swar_fleet"
gcc -O3 -Wall -Wextra -fPIC -shared eo_probe/core/swar_fleet.c -o eo_probe/core/libswar_fleet.so
echo "    eo_probe/core/libswar_fleet.so"

FRIC_DIR="vendor/smart_token_prod/cpp"
if [[ -f "${FRIC_DIR}/friction_core.cpp" ]]; then
  echo "==> Building SmartTokenProd friction core (libfriction.so)"
  (cd "${FRIC_DIR}" && make all)
  # Place next to the Python package for ctypes discovery
  cp -f "${FRIC_DIR}/libfriction.so" vendor/smart_token_prod/libfriction.so
  echo "    vendor/smart_token_prod/libfriction.so"
else
  echo "==> SmartTokenProd C++ sources not present — skipping friction core"
fi

echo ""
echo "Native build complete."
ls -la build/libmorph8.so eo_probe/core/libswar_fleet.so 2>/dev/null || true
ls -la vendor/smart_token_prod/libfriction.so 2>/dev/null || true
