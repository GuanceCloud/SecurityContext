#!/usr/bin/env python3
"""Write an external release-validation manifest from completed QA artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


REQUIRED_FRAMEWORKS = frozenset({"fastapi", "flask", "django"})


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact(path: Path, root: Path) -> dict[str, str]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        display = path.relative_to(root.resolve()).as_posix()
    except ValueError:
        display = str(path)
    return {"path": display, "sha256": sha256(path)}


def _content_digest(entries: dict[str, bytes]) -> dict[str, object]:
    digest = hashlib.sha256()
    for name in sorted(entries):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(entries[name])
        digest.update(b"\0")
    return {"members": len(entries), "sha256": digest.hexdigest()}


def _wheel_subset(path: Path, predicate) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {
            name: archive.read(name)
            for name in archive.namelist()
            if not name.endswith("/") and predicate(name)
        }


def _source_subset(root: Path, relative_root: Path, prefix: str, predicate) -> dict[str, bytes]:
    source_root = root / relative_root
    if not source_root.is_dir():
        return {}
    return {
        prefix + path.relative_to(source_root).as_posix(): path.read_bytes()
        for path in source_root.rglob("*")
        if path.is_file() and predicate(path)
    }


def _compare_entries(left: dict[str, bytes], right: dict[str, bytes]) -> dict[str, object]:
    left_report = _content_digest(left)
    right_report = _content_digest(right)
    return {
        "same": left == right,
        "left": left_report,
        "right": right_report,
        "left_only": sorted(set(left) - set(right)),
        "right_only": sorted(set(right) - set(left)),
    }


def content_identity(root: Path, release_wheel: Path, benchmark_report: dict) -> dict[str, object]:
    """Compare release contents without treating packaged documentation as code."""

    benchmark_wheel_value = benchmark_report.get("wheel", {}).get("path")
    if not benchmark_wheel_value:
        return {"passed": False, "reason": "benchmark_wheel_path_missing"}
    benchmark_wheel = Path(str(benchmark_wheel_value))
    if not benchmark_wheel.is_file():
        return {"passed": False, "reason": f"benchmark_wheel_missing:{benchmark_wheel}"}

    declared_hash = benchmark_report.get("wheel", {}).get("sha256")
    actual_hash = sha256(benchmark_wheel)
    production = lambda name: name.startswith("securitycontext/") and name.endswith(".py") and not name.startswith("securitycontext/data/")
    samples = lambda name: name.startswith("securitycontext/data/samples/")
    benchmark_code = _wheel_subset(benchmark_wheel, production)
    release_code = _wheel_subset(release_wheel, production)
    benchmark_samples = _wheel_subset(benchmark_wheel, samples)
    release_samples = _wheel_subset(release_wheel, samples)

    source_code = _source_subset(
        root,
        Path("python/src/securitycontext"),
        "securitycontext/",
        lambda path: path.suffix == ".py",
    )
    canonical_cli = root / "scripts" / "securityctl.py"
    if canonical_cli.is_file():
        source_code["securitycontext/_securityctl.py"] = canonical_cli.read_bytes()
    source_samples = _source_subset(
        root,
        Path("python/samples"),
        "securitycontext/data/samples/",
        lambda path: path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc",
    )

    fixture_path = root / "python/samples/security_sample/benchmark_app.py"
    fixture_declared = benchmark_report.get("fixture", {}).get("sha256")
    fixture_actual = sha256(fixture_path) if fixture_path.is_file() else ""
    comparisons = {
        "benchmark_wheel_vs_release_wheel": {
            "production_code": _compare_entries(benchmark_code, release_code),
            "samples": _compare_entries(benchmark_samples, release_samples),
            "docs_excluded": True,
        },
        "source_vs_release_wheel": {
            "production_code": _compare_entries(source_code, release_code),
            "samples": _compare_entries(source_samples, release_samples),
            "docs_excluded": True,
        },
        "benchmark_fixture": {
            "path": str(fixture_path.relative_to(root)),
            "declared_sha256": fixture_declared,
            "actual_sha256": fixture_actual,
            "same": bool(fixture_declared) and fixture_declared == fixture_actual,
        },
    }
    same = all(
        comparisons[group][part]["same"]
        for group in ("benchmark_wheel_vs_release_wheel", "source_vs_release_wheel")
        for part in ("production_code", "samples")
    ) and comparisons["benchmark_fixture"]["same"] and declared_hash == actual_hash
    return {
        "passed": same,
        "benchmark_wheel": {"path": str(benchmark_wheel), "sha256": actual_hash, "declared_sha256": declared_hash},
        "comparisons": comparisons,
    }


def named_artifact(value: str, root: Path) -> tuple[str, dict[str, str]]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise ValueError(f"artifact must be NAME=PATH: {value}")
    return name, artifact(Path(path), root)


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def successful(path: Path, key: str = "passed") -> bool:
    return read_json(path).get(key) is True


def report_with_checks(path: Path) -> bool:
    report = read_json(path)
    checks = report.get("checks")
    return (
        report.get("passed") is True
        and isinstance(checks, dict)
        and bool(checks)
        and all(value is True for value in checks.values())
    )


def unit_successful(path: Path) -> bool:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return False
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    try:
        test_count = sum(int(suite.attrib.get("tests", "0")) for suite in suites)
    except (TypeError, ValueError):
        return False
    if test_count == 0:
        test_count = len(root.findall(".//testcase"))
    return (
        test_count > 0
        and all(int(suite.attrib.get("errors", "0")) == 0 for suite in suites)
        and all(int(suite.attrib.get("failures", "0")) == 0 for suite in suites)
        and root.find(".//error") is None
        and root.find(".//failure") is None
    )


def clients_successful(paths: list[Path]) -> bool:
    if not paths:
        return False
    for path in paths:
        report = read_json(path)
        cases = report.get("cases")
        passed = report.get("passed")
        if (
            not isinstance(cases, list)
            or not cases
            or isinstance(passed, bool)
            or not isinstance(passed, int)
            or passed != len(cases)
            or report.get("failed") != 0
            or report.get("unverified") != 0
            or any(
                not isinstance(case, dict) or case.get("status") != "passed"
                for case in cases
            )
        ):
            return False
    return True


def collector_successful(path: Path) -> bool:
    report = read_json(path)
    required_checks = (
        "all_log_bodies_are_json_security_dataflow",
        "all_server_span_ids_match_debug_and_evidence",
        "all_trace_ids_match_debug_and_evidence",
    )
    counts = (
        report.get("collector_security_dataflow_log_count"),
        report.get("local_evidence_event_count"),
        report.get("matched_evidence_count"),
    )
    return (
        report.get("status") == "passed"
        and all(report.get(check) is True for check in required_checks)
        and isinstance(counts[0], int)
        and counts[0] > 0
        and counts[0] == counts[1] == counts[2]
    )


def form_successful(paths: list[Path]) -> bool:
    if len(paths) != len(REQUIRED_FRAMEWORKS):
        return False
    reports = [read_json(path) for path in paths]
    frameworks = {report.get("framework") for report in reports}
    required_checks = {
        "form_dataflow_source",
        "text_dataflow_source",
        "form_parameterized_negative",
        "text_parameterized_negative",
    }
    return (
        frameworks == REQUIRED_FRAMEWORKS
        and all(
            report.get("passed") is True
            and isinstance(report.get("checks"), dict)
            and all(report["checks"].get(check) is True for check in required_checks)
            for report in reports
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-report", type=Path, required=True)
    parser.add_argument(
        "--release-dist",
        type=Path,
        help="directory containing the selected final wheel, sdist and SHA256SUMS",
    )
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--shutdown-hook", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--clients", type=Path, nargs="+", required=True)
    parser.add_argument("--framework", action="append", default=[])
    parser.add_argument("--form", type=Path, nargs="+", required=True)
    parser.add_argument("--unit", type=Path, required=True)
    parser.add_argument("--constraints", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    package_path = args.package_report.resolve()
    package = read_json(package_path)
    final_dist = package.get("final_dist", {})
    build_release = Path(
        final_dist.get(
            "release_wheel_from_sdist",
            package["release_wheel_from_sdist"]["path"],
        )
    )
    build_sdist = Path(final_dist.get("sdist", package["sdist"]["path"]))
    delivery_dist = args.release_dist.resolve() if args.release_dist else None
    release = (
        delivery_dist / build_release.name
        if delivery_dist is not None
        else build_release
    )
    sdist = delivery_dist / build_sdist.name if delivery_dist is not None else build_sdist
    sha256sums_path = (
        delivery_dist / "SHA256SUMS"
        if delivery_dist is not None
        else Path(package["sha256sums"])
    )
    framework_paths = {}
    frameworks = {}
    for value in args.framework:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise ValueError(f"artifact must be NAME=PATH: {value}")
        framework_paths[name] = Path(path)
        frameworks[name] = artifact(Path(path), root)
    form_paths = [Path(path) for path in args.form]
    form = [artifact(path, root) for path in form_paths]
    clients = [artifact(path, root) for path in args.clients]
    benchmark_data = read_json(args.benchmark)
    shutdown_hook = read_json(args.shutdown_hook)
    try:
        identity = content_identity(root, release, benchmark_data)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        identity = {"passed": False, "reason": f"content_identity_error:{type(error).__name__}:{error}"}
    matrix_ok = successful(args.matrix)
    framework_ok = (
        len(args.framework) == len(REQUIRED_FRAMEWORKS)
        and set(framework_paths) == REQUIRED_FRAMEWORKS
        and all(report_with_checks(path) for path in framework_paths.values())
    )
    form_ok = form_successful(form_paths)
    benchmark_ok = benchmark_data.get("valid") is True
    shutdown_hook_ok = shutdown_hook.get("passed") is True
    package_smoke_ok = package.get("installed_wheel_smoke", {}).get("returncode") == 0
    unit_ok = unit_successful(args.unit)
    clients_ok = clients_successful(list(args.clients))
    product_ok = report_with_checks(args.product)
    collector_ok = collector_successful(args.collector)
    content_identity_ok = identity.get("passed") is True
    release_checks = {
        "package_installed_wheel_smoke": package_smoke_ok,
        "unit_suite": unit_ok,
        "matrix": matrix_ok,
        "installed_framework_smoke": framework_ok,
        "form_text_312": form_ok,
        "clients": clients_ok,
        "product": product_ok,
        "collector": collector_ok,
        "benchmark": benchmark_ok,
        "shutdown_hook": shutdown_hook_ok,
        "source_and_benchmark_content_identity": content_identity_ok,
    }
    blocking_reasons = [name for name, passed in release_checks.items() if not passed]
    manifest = {
        "schema_version": 1,
        "source": "security_context",
        "status": "validated" if not blocking_reasons else "blocked",
        "release_checks": release_checks,
        "blocking_reasons": blocking_reasons,
        "platform_note": "Linux/aarch64 shared OrbStack; x86_64 unverified; benchmark is measured_not_sla.",
        "package": {
            "report": artifact(package_path, root),
            "release_wheel_from_sdist": artifact(release, root),
            "sdist": artifact(sdist, root),
            "sha256sums": artifact(sha256sums_path, root),
            "delivery_directory": (
                str(delivery_dist.relative_to(root))
                if delivery_dist is not None
                else str(Path(package.get("final_dist", {}).get("directory", "")))
            ),
            "checksum_scope": package.get("checksum_scope", {}),
            "installed_wheel_smoke": package.get("installed_wheel_smoke", {}),
        },
        "unit_suite": artifact(args.unit, root),
        "framework_matrix": artifact(args.matrix, root),
        "framework_smoke_installed_wheel": frameworks,
        "form_text_312": form,
        "clients": clients,
        "product": artifact(args.product, root),
        "collector": artifact(args.collector, root),
        "benchmark": artifact(args.benchmark, root),
        "content_identity": identity,
        "shutdown_hook": artifact(args.shutdown_hook, root),
        "constraints": artifact(args.constraints, root),
    }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if not blocking_reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
