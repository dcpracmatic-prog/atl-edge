#!/usr/bin/env python3
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.atl_core import run_selftest
raise SystemExit(0 if run_selftest() else 1)
