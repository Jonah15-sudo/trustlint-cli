#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=. python -m unittest discover -s tests -v
python -m compileall -q spl_v7 examples tests
