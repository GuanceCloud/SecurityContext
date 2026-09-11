from __future__ import annotations

import sys
from pathlib import Path


PYTHON_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PYTHON_ROOT / "src"
SAMPLES_ROOT = PYTHON_ROOT / "samples"

for path in (SRC_ROOT, SAMPLES_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
