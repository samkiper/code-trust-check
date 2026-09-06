#!/usr/bin/env bash
set -euo pipefail

python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/run_accuracy_gate.py --download-official --limit 750 --report accuracy-report.json
