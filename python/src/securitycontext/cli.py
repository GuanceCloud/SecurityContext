from __future__ import annotations

import importlib.util
from pathlib import Path


def main():
    try:
        from ._securityctl import main as shared_main
    except ModuleNotFoundError as error:
        if error.name != "securitycontext._securityctl":
            raise
        source = Path(__file__).resolve().parents[3] / "scripts" / "securityctl.py"
        if not source.is_file():
            raise RuntimeError("Shared securityctl source is missing; reinstall the release wheel") from error
        spec = importlib.util.spec_from_file_location("_securitycontextctl", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        shared_main = module.main
    return shared_main()


if __name__ == "__main__":
    raise SystemExit(main())
