#!/usr/bin/env python3
"""
Unified testbench entry point for SmartTokenProd (adversarial + status).

Usage:
  python testbench/run_testbench.py
  python testbench/run_testbench.py --json /tmp/stp-adversarial.json
  python testbench/run_testbench.py --require-full
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from adversarial_battery import main

if __name__ == "__main__":
    sys.exit(main())
