#!/usr/bin/env python3
"""Execute the Python 3.11-3.14 x FastAPI/Flask/Django matrix in containers."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


VERSIONS = ("311", "312", "313", "314")
FRAMEWORKS = ("fastapi", "flask", "django")
WORKSPACE = Path(__file__).resolve().parents[2]


def docker_output(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True).strip()


def container_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(WORKSPACE)
    except ValueError:
        return str(path)
    return "/workspace/" + relative.as_posix()


def run_leg(version: str, framework: str, output: Path) -> dict:
    container = f"securitycontext-py-{version}"
    try:
        state = docker_output("inspect", "--format", "{{.State.Status}}", container)
        machine = docker_output("exec", container, "uname", "-m")
    except (OSError, subprocess.CalledProcessError) as error:
        return {"version": version, "framework": framework, "status": "unavailable", "error": str(error)}
    if state != "running":
        return {"version": version, "framework": framework, "status": "unavailable", "error": f"container={state}"}
    leg = output / version / framework
    leg.mkdir(parents=True, exist_ok=True)
    command = [
        "docker",
        "exec",
        f"securitycontext-py-{version}",
        "python",
        f"/workspace/python/scripts/run_framework_case.py",
        "--framework",
        framework,
        "--output",
        container_path(output / version / framework),
    ]
    completed = subprocess.run(command, text=True, capture_output=True)
    (leg / "stdout.log").write_text(completed.stdout, encoding="utf-8")
    (leg / "stderr.log").write_text(completed.stderr, encoding="utf-8")
    summary_path = leg / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["container"] = container
        summary["container_architecture"] = machine
        summary["returncode"] = completed.returncode
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return summary
    return {
        "version": version,
        "framework": framework,
        "container": container,
        "container_architecture": machine,
        "status": "failed",
        "returncode": completed.returncode,
        "stderr": completed.stderr[-2000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", choices=VERSIONS, action="append", dest="versions")
    parser.add_argument("--framework", choices=FRAMEWORKS, action="append", dest="frameworks")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("build/validation/python-v01/matrix"),
    )
    args = parser.parse_args()
    versions = args.versions or list(VERSIONS)
    frameworks = args.frameworks or list(FRAMEWORKS)
    args.output.mkdir(parents=True, exist_ok=True)
    legs = [run_leg(version, framework, args.output) for version in versions for framework in frameworks]
    report = {
        "schema_version": 2,
        "source": "security_context",
        "host_architecture": platform.machine(),
        "docker_context": docker_output("context", "show"),
        "tested_architecture": "linux/arm64",
        "x86_64": "unverified unless a separate x86_64 run is supplied",
        "legs": legs,
        "passed": all(leg.get("passed") is True for leg in legs),
    }
    path = args.output / "matrix-summary.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
