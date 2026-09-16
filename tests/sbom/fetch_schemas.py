#!/usr/bin/env python3
"""Fetch the pinned CycloneDX 1.7 JSON schemas used by contract tests."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import tempfile
import urllib.request


BASE_URL = "https://raw.githubusercontent.com/CycloneDX/specification/1.7/schema"
REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMAS = {
    "cyclonedx-bom-1.7.schema.json": (
        "bom-1.7.schema.json",
        "df472ef4aaf593904c479293723a1a5c191d6672715c93b3c0b5c318f3914221",
    ),
    "cryptography-defs.schema.json": (
        "cryptography-defs.schema.json",
        "018ea7f78b5208ec647cfd10f669cc9c26aba6aceb79c4da7f9c0ef4c99b60de",
    ),
    "jsf-0.82.schema.json": (
        "jsf-0.82.schema.json",
        "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    ),
    "spdx.schema.json": (
        "spdx.schema.json",
        "54a6288292bc6c90b0d3952f5f939f17436fa76704ffe68a46e5b78539c7cc1b",
    ),
}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(output: pathlib.Path, timeout: float) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for local_name, (remote_name, expected) in SCHEMAS.items():
        target = output / local_name
        if target.is_file() and digest(target) == expected:
            print(f"verified {target}")
            continue

        url = f"{BASE_URL}/{remote_name}"
        with urllib.request.urlopen(url, timeout=timeout) as response:
            content = response.read()
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise SystemExit(
                f"checksum mismatch for {url}: expected {expected}, got {actual}"
            )

        with tempfile.NamedTemporaryFile(dir=output, delete=False) as temporary:
            temporary.write(content)
            temporary_path = pathlib.Path(temporary.name)
        temporary_path.replace(target)
        print(f"downloaded {target}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=REPOSITORY_ROOT / "build" / "validation" / "sbom",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    arguments = parser.parse_args()
    fetch(arguments.output, arguments.timeout)


if __name__ == "__main__":
    main()
