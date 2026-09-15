#!/usr/bin/env bash
# Build and run script for MORPH-8 C++ fuzzer harness using libFuzzer / AddressSanitizer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

HARNESS="${ROOT_DIR}/testbench/fuzz_morph8.cpp"
SOURCE="${ROOT_DIR}/src/morph8.cpp"
CORPUS="${ROOT_DIR}/testbench/fuzz_corpus"
OUTPUT_BIN="${ROOT_DIR}/testbench/fuzz_morph8"

echo "=== Building MORPH-8 libFuzzer Harness ==="

if command -v clang++ &>/dev/null; then
    COMPILER="clang++"
else
    echo "clang++ not found. Fuzzing harness build requires clang++ with libFuzzer support."
    exit 0
fi

${COMPILER} -std=c++17 -O2 -g -fsanitize=fuzzer,address \
    "${HARNESS}" "${SOURCE}" \
    -o "${OUTPUT_BIN}"

echo "Build successful: ${OUTPUT_BIN}"

if [ "${1:-}" == "--run" ]; then
    echo "=== Running MORPH-8 Fuzzer ==="
    "${OUTPUT_BIN}" "${CORPUS}" -max_total_time=10 -max_len=65536
fi
