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

# Smart Token Prod is installed from git (see requirements.txt) and its wheel
# does NOT ship the cpp/ sources, so the optional friction core is built from a
# source checkout of the same pinned tag. The .so is dropped next to the
# installed package, which is where smart_token_prod.native looks for it.
# Native friction is OPTIONAL: without it the pure-Python tarpit is used, so a
# failure here must not fail the build.
STP_TAG="${STP_TAG:-v0.10.4}"
STP_SRC="third_party/Smart-Token-Prod-${STP_TAG}"

echo "==> Building SmartTokenProd friction core (libfriction.so, optional)"
PKG_DIR="$(python3 -c 'import os,smart_token_prod;print(os.path.dirname(smart_token_prod.__file__))' 2>/dev/null || true)"
if [[ -z "${PKG_DIR}" ]]; then
  echo "    smart_token_prod not importable — run 'pip install -r requirements.txt' first; skipping"
elif ! command -v g++ >/dev/null 2>&1; then
  echo "    g++ not found — skipping (pure-Python tarpit will be used)"
else
  if [[ ! -f "${STP_SRC}/cpp/friction_core.cpp" ]]; then
    echo "    fetching ${STP_TAG} sources for the C++ core"
    mkdir -p third_party
    rm -rf "${STP_SRC}"
    git -c advice.detachedHead=false clone -q --depth 1 --branch "${STP_TAG}" \
      https://github.com/dcpracmatic-prog/Smart-Token-Prod.git "${STP_SRC}" \
      || echo "    clone failed (offline?) — skipping native friction"
  fi
  if [[ -f "${STP_SRC}/cpp/friction_core.cpp" ]]; then
    (cd "${STP_SRC}/cpp" && make libfriction.so >/dev/null)
    cp -f "${STP_SRC}/cpp/libfriction.so" build/libfriction.so
    cp -f "${STP_SRC}/cpp/libfriction.so" "${PKG_DIR}/libfriction.so"
    echo "    ${PKG_DIR}/libfriction.so"
    python3 -c 'from smart_token_prod.native import is_available; print("    native friction available:", is_available())'
  fi
fi

echo ""
echo "Native build complete."
ls -la build/libmorph8.so eo_probe/core/libswar_fleet.so 2>/dev/null || true
ls -la build/libfriction.so 2>/dev/null || true
