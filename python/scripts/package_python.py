#!/usr/bin/env python3
"""Build and verify the Python release from checkout and sdist inputs."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
CANONICAL_CLI = WORKSPACE / "scripts" / "securityctl.py"
COLLECTOR_CONFIG = WORKSPACE / "deploy" / "otel-collector-config.yaml"
PACKAGE_NAME = "securitycontext"
PACKAGE_VERSION = "0.2.5"


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(str(item) for item in command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def preflight() -> None:
    required = [
        ROOT / "README.md",
        ROOT / "README.en.md",
        ROOT / "docs" / "guide.zh-CN.md",
        ROOT / "docs" / "guide.en.md",
        ROOT / "setup.py",
        ROOT / "pyproject.toml",
        CANONICAL_CLI,
        COLLECTOR_CONFIG,
        ROOT / "samples" / "security_sample" / "fastapi_app.py",
        ROOT / "samples" / "security_sample" / "flask_app.py",
        ROOT / "samples" / "security_sample" / "django_app.py",
        ROOT / "samples" / "security_sample" / "benchmark_app.py",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if not list(ROOT.glob("constraints*.txt")):
        missing.append(str(ROOT / "constraints*.txt"))
    if not (ROOT / "docs").is_dir() or not any((ROOT / "docs").glob("*.md")):
        missing.append(str(ROOT / "docs" / "*.md"))
    if missing:
        raise FileNotFoundError("release inputs are incomplete: " + ", ".join(missing))


def one_match(directory: Path, suffix: str) -> Path:
    matches = sorted(directory.glob(f"*{suffix}"))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {suffix} in {directory}, found {matches}")
    return matches[0]


def safe_extract(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        root = destination.resolve()
        for member in members:
            if member.issym() or member.islnk():
                raise RuntimeError(f"unsafe sdist link member: {member.name}")
            target = (root / member.name).resolve()
            try:
                common = os.path.commonpath((str(root), str(target)))
            except ValueError as error:
                raise RuntimeError(f"unsafe sdist member: {member.name}") from error
            if common != str(root):
                raise RuntimeError(f"unsafe sdist member: {member.name}")
        if sys.version_info >= (3, 12):
            stream.extractall(destination, filter="data")
        else:
            stream.extractall(destination)
    roots = sorted(path for path in destination.iterdir() if path.is_dir())
    if len(roots) != 1:
        raise RuntimeError(f"sdist must contain one root directory, found {roots}")
    return roots[0]


def wheel_members(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        return archive.namelist()


def wheel_file(wheel: Path, member: str) -> bytes:
    with zipfile.ZipFile(wheel) as archive:
        return archive.read(member)


def verify_sdist(archive: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="securitycontext-sdist-check-") as temporary:
        root = safe_extract(archive, Path(temporary))
        names = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        }
    required = {
        "setup.py",
        "README.md",
        "README.en.md",
        "_shared/securityctl.py",
        "_shared/otel-collector-config.yaml",
        "samples/security_sample/fastapi_app.py",
        "samples/security_sample/flask_app.py",
        "samples/security_sample/django_app.py",
        "samples/security_sample/benchmark_app.py",
    }
    required.update(path.name for path in ROOT.glob("constraints*.txt"))
    required.update(path.relative_to(ROOT).as_posix() for path in (ROOT / "docs").glob("*.md"))
    missing = sorted(required - names)
    if missing:
        raise RuntimeError(f"sdist is missing release inputs: {missing}")
    return {"members": len(names), "required": sorted(required)}


def verify_wheel(wheel: Path) -> dict:
    members = set(wheel_members(wheel))
    package_prefix = "securitycontext/"
    required = {
        package_prefix + "_securityctl.py",
        package_prefix + "data/README.md",
        package_prefix + "data/README.en.md",
        package_prefix + "data/otel-collector-config.yaml",
        package_prefix + "data/samples/security_sample/fastapi_app.py",
        package_prefix + "data/samples/security_sample/flask_app.py",
        package_prefix + "data/samples/security_sample/django_app.py",
        package_prefix + "data/samples/security_sample/benchmark_app.py",
    }
    required.update(
        package_prefix + "data/" + path.name for path in ROOT.glob("constraints*.txt")
    )
    required.update(
        package_prefix + "data/docs/" + path.name for path in (ROOT / "docs").glob("*.md")
    )
    missing = sorted(required - members)
    if missing:
        raise RuntimeError(f"wheel is missing package data: {missing}")

    cli_hash = hashlib.sha256(CANONICAL_CLI.read_bytes()).hexdigest()
    packaged_cli_hash = hashlib.sha256(wheel_file(wheel, package_prefix + "_securityctl.py")).hexdigest()
    if packaged_cli_hash != cli_hash:
        raise RuntimeError(f"packaged securityctl SHA256 differs: {packaged_cli_hash} != {cli_hash}")

    metadata_member = next(
        member for member in members if member.endswith(".dist-info/entry_points.txt")
    )
    entry_points = wheel_file(wheel, metadata_member).decode("utf-8")
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    try:
        parser.read_string(entry_points)
    except configparser.Error as error:
        raise RuntimeError("wheel entry points are not valid INI") from error
    expected_entry_points = {
        "console_scripts": {"securityctl": "securitycontext.cli:main"},
        "opentelemetry_instrumentor": {
            "securitycontext": "securitycontext:SecurityInstrumentor"
        },
        "opentelemetry_pre_instrument": {
            "securitycontext": "securitycontext:bootstrap"
        },
    }
    missing_entry_points = [
        f"{section}:{name}"
        for section, entries in expected_entry_points.items()
        for name, value in entries.items()
        if not parser.has_option(section, name) or parser.get(section, name).strip() != value
    ]
    if missing_entry_points:
        raise RuntimeError(
            "wheel entry points are missing required mappings: "
            + ", ".join(missing_entry_points)
        )
    return {
        "members": len(members),
        "required": sorted(required),
        "canonical_cli_sha256": cli_hash,
        "packaged_cli_sha256": packaged_cli_hash,
        "entry_points_member": metadata_member,
    }


def run_installed_smoke(wheel: Path, report_dir: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="securitycontext-wheel-", dir="/tmp") as temporary:
        virtualenv = Path(temporary) / "venv"
        venv.EnvBuilder(with_pip=True, system_site_packages=True, clear=False).create(virtualenv)
        interpreter = virtualenv / "bin" / "python"
        run([str(interpreter), "-m", "pip", "install", "--no-deps", "--force-reinstall", str(wheel)])
        smoke = Path(temporary) / "smoke.py"
        smoke.write_text(
            """\
import json
import pathlib
import subprocess
import sys
import tempfile
from securitycontext import SecurityInstrumentor, bootstrap, runtime
from securitycontext.cli import main as cli_main
from securitycontext.transform import transform

assert 'site-packages' in str(__import__('securitycontext').__file__)
assert callable(SecurityInstrumentor) and callable(bootstrap) and callable(cli_main)
cli = pathlib.Path(sys.executable).with_name('securityctl')
cli_result = subprocess.run([str(cli), '--help'], capture_output=True, text=True, check=False)
assert cli_result.returncode == 0 and 'usage' in cli_result.stdout.lower()
state = runtime.start_request({'route': '/wheel-smoke'})
assert state is not None
token = runtime.attach_state(state)
try:
    value = ''.join(('wheel', '-query'))
    runtime.source(value, 'http.request.parameter', 'q')
    namespace = {'__name__': 'wheel_smoke', 'runtime': runtime}
    tree = transform(
        '''def make(value):
    return f"select {value!r}"
''',
        'wheel_smoke.py',
        'wheel_smoke',
    )
    exec(compile(tree, 'wheel_smoke.py', 'exec'), namespace)
    result = namespace['make'](value)
    assert type(result) is str and state.marks(result)
    event = runtime.sink('sql_injection', 'sqlite3.Connection.execute', 'template', result,
                         marks=state.marks(result), location='wheel_smoke')
    assert event is not None and value not in json.dumps(event, sort_keys=True)
finally:
    runtime.end_request(state)
    runtime.detach_state(token)
    assert runtime.get_runtime().exporter.flush(timeout=5.0)
    runtime.stop()
import importlib.resources as resources
assert resources.files('securitycontext').joinpath('data', 'otel-collector-config.yaml').is_file()
print('wheel smoke passed')
""",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = ""
        environment.update(
            {
                "SECURITY_ENABLED": "true",
                "SECURITY_PYTHON_INCLUDE": "wheel_smoke",
                "SECURITY_PYTHON_EXCLUDE": "",
                "SECURITY_OUTPUT": str(Path(temporary) / "security-output"),
                "SECURITY_EVIDENCE_FILE": str(Path(temporary) / "security-output" / "evidence.jsonl"),
                "SECURITY_SBOM_ENABLED": "false",
                "OTEL_TRACES_EXPORTER": "none",
                "OTEL_METRICS_EXPORTER": "none",
                "OTEL_LOGS_EXPORTER": "none",
            }
        )
        result = subprocess.run(
            [str(interpreter), str(smoke)],
            cwd=report_dir,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        (report_dir / "wheel-smoke.stdout.txt").write_text(result.stdout, encoding="utf-8")
        (report_dir / "wheel-smoke.stderr.txt").write_text(result.stderr, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"non-editable wheel smoke failed with {result.returncode}: {result.stderr}")
        return {"returncode": result.returncode, "stdout": result.stdout.strip()}


def package(output: Path) -> dict:
    preflight()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    checkout_dist = output / "checkout-dist"
    checkout_wheel = output / "checkout-wheel"
    from_sdist = output / "from-sdist"
    for directory in (checkout_dist, checkout_wheel, from_sdist):
        directory.mkdir(parents=True, exist_ok=True)

    run([sys.executable, "-m", "build", "--no-isolation", "--sdist", "--outdir", str(checkout_dist)], cwd=ROOT)
    sdist = one_match(checkout_dist, ".tar.gz")
    sdist_report = verify_sdist(sdist)

    run([sys.executable, "-m", "build", "--no-isolation", "--wheel", "--outdir", str(checkout_wheel)], cwd=ROOT)
    direct_wheel = one_match(checkout_wheel, ".whl")
    direct_report = verify_wheel(direct_wheel)

    with tempfile.TemporaryDirectory(prefix="securitycontext-sdist-build-") as temporary:
        extracted = safe_extract(sdist, Path(temporary))
        run(
            [sys.executable, "-m", "build", "--no-isolation", "--wheel", "--outdir", str(from_sdist)],
            cwd=extracted,
        )
    release_wheel = one_match(from_sdist, ".whl")
    release_report = verify_wheel(release_wheel)
    smoke_report = run_installed_smoke(release_wheel, output)

    final_dist = output / "dist"
    final_dist.mkdir(parents=True, exist_ok=True)
    final_sdist = final_dist / sdist.name
    final_wheel = final_dist / release_wheel.name
    shutil.copy2(sdist, final_sdist)
    shutil.copy2(release_wheel, final_wheel)
    checksums = {
        final_sdist.name: sha256(final_sdist),
        final_wheel.name: sha256(final_wheel),
    }
    checksum_file = final_dist / "SHA256SUMS"
    checksum_file.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items())),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "source": "security_context",
        "package": PACKAGE_NAME,
        "version": PACKAGE_VERSION,
        "sdist": {"path": str(sdist), **sdist_report},
        "direct_wheel": {"path": str(direct_wheel), **direct_report},
        "release_wheel_from_sdist": {"path": str(release_wheel), **release_report},
        "installed_wheel_smoke": smoke_report,
        "sha256sums": str(checksum_file),
        "artifact_sha256": checksums,
        "final_dist": {
            "directory": str(final_dist),
            "sdist": str(final_sdist),
            "release_wheel_from_sdist": str(final_wheel),
        },
        "checksum_scope": {
            "selected_release": str(final_wheel),
            "entries": [final_sdist.name, final_wheel.name],
            "direct_wheel_name": direct_wheel.name,
            "direct_wheel_sha256": sha256(direct_wheel),
            "release_wheel_sha256": sha256(release_wheel),
            "same_filename_overwrites_direct_entry": direct_wheel.name == release_wheel.name,
        },
    }
    (output / "package-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = package(args.output.resolve())
    except Exception as error:
        print(json.dumps({"source": "security_context", "passed": False, "error": f"{type(error).__name__}: {error}"}, indent=2))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
