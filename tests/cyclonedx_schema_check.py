#!/usr/bin/env python3
"""Validate a CycloneDX JSON document without adding a schema dependency.

The full schema validation is performed by the optional `check-jsonschema`
gate in scripts/validate_injection.sh when network/package access is present.
This check keeps the local acceptance gate deterministic and verifies the
fields the extension promises to emit.
"""

import json
import pathlib
import sys


def fail(message: str) -> None:
    print(f"SBOM validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(
    "build/validation/application.cdx.json"
)
try:
    document = json.loads(path.read_text(encoding="utf-8"))
except FileNotFoundError:
    fail(f"file does not exist: {path}")
except json.JSONDecodeError as exc:
    fail(f"invalid JSON: {exc}")

if document.get("bomFormat") != "CycloneDX":
    fail("bomFormat must be CycloneDX")
if not isinstance(document.get("specVersion"), str):
    fail("specVersion must be present")
if not isinstance(document.get("serialNumber"), str) or not document["serialNumber"].startswith("urn:uuid:"):
    fail("serialNumber must be a UUID URN")
if not isinstance(document.get("version"), int) or document["version"] < 1:
    fail("version must be a positive integer")
components = document.get("components")
if not isinstance(components, list):
    fail("components must be an array")
for index, component in enumerate(components):
    if not isinstance(component, dict):
        fail(f"components[{index}] must be an object")
    if not isinstance(component.get("bom-ref"), str) or not component["bom-ref"]:
        fail(f"components[{index}] is missing bom-ref")
    if not isinstance(component.get("name"), str) or not component["name"]:
        fail(f"components[{index}] is missing name")
    if "hashes" in component and not isinstance(component["hashes"], list):
        fail(f"components[{index}].hashes must be an array")
    for hash_item in component.get("hashes", []):
        if not isinstance(hash_item, dict) or hash_item.get("alg") != "SHA-256" or not hash_item.get("content"):
            fail(f"components[{index}] has an invalid SHA-256 entry")
print(f"CycloneDX structural validation passed: {path} ({len(components)} components)")
