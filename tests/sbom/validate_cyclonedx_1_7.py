#!/usr/bin/env python3
"""Validate CycloneDX 1.7 JSON with the downloaded official schema and refs."""

import argparse
import json
import pathlib
import sys
import warnings
from urllib.parse import urlparse

warnings.simplefilter("ignore", DeprecationWarning)

try:
    from jsonschema import Draft7Validator, FormatChecker, RefResolver
except ImportError as error:  # pragma: no cover - exercised by the command-line gate
    raise SystemExit(
        "jsonschema is required; install jsonschema>=4.23 in the validation environment"
    ) from error


REQUIRED_REFS = (
    "cryptography-defs.schema.json",
    "jsf-0.82.schema.json",
    "spdx.schema.json",
)


def load_json(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"cannot read JSON {path}: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "documents",
        nargs="+",
        type=pathlib.Path,
        help="CycloneDX JSON documents to validate",
    )
    parser.add_argument(
        "--schema-dir",
        type=pathlib.Path,
        default=pathlib.Path("build/validation/sbom"),
        help="cache containing bom-1.7 and its external schema references",
    )
    args = parser.parse_args()
    schema_dir = args.schema_dir
    schema_path = schema_dir / "cyclonedx-bom-1.7.schema.json"
    schema = load_json(schema_path)
    if schema.get("$id") != "http://cyclonedx.org/schema/bom-1.7.schema.json":
        raise SystemExit(f"unexpected schema id in {schema_path}: {schema.get('$id')}")
    missing = [name for name in REQUIRED_REFS if not (schema_dir / name).is_file()]
    if missing:
        raise SystemExit("missing cached schema references: " + ", ".join(missing))

    Draft7Validator.check_schema(schema)

    def resolve_cached(uri):
        name = pathlib.PurePosixPath(urlparse(uri).path).name
        path = schema_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"uncached schema reference: {uri}")
        return load_json(path)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = RefResolver.from_schema(
            schema, handlers={"http": resolve_cached, "https": resolve_cached}
        )
        validator = Draft7Validator(
            schema, resolver=resolver, format_checker=FormatChecker()
        )
        failed = False
        print(f"schema: {schema_path}")
        print("refs: " + ", ".join(REQUIRED_REFS))
        for document_path in args.documents:
            document = load_json(document_path)
            errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
            if errors:
                failed = True
                print(f"FAIL {document_path}: {len(errors)} schema error(s)")
                for error in errors:
                    location = "/".join(str(part) for part in error.path) or "$"
                    schema_location = "/".join(str(part) for part in error.schema_path)
                    print(f"  {location}: {error.message} (schema {schema_location})")
            else:
                print(f"PASS {document_path}: CycloneDX 1.7 official JSON Schema")
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
