# SBOM schema acceptance

`validate_cyclonedx_1_7.py` validates generated output against the official
CycloneDX 1.7 JSON Schema and its external schema references. The validation
cache is populated under `build/validation/sbom` by the OrbStack validation
run; it contains the main schema, `cryptography-defs.schema.json`,
`jsf-0.82.schema.json`, and `spdx.schema.json`.

The checked-in `application-cdx-1.7-anonymized.json` is a sanitized fixture
with no host paths, process IDs, UUIDs from a live run, or application
identifiers. It has passed the same official-schema gate as the generated
`build/debug/application.cdx.json`.

Example validation command after installing `jsonschema` in the validation
container:

```bash
python3 tests/sbom/validate_cyclonedx_1_7.py \
  --schema-dir build/validation/sbom \
  build/debug/application.cdx.json \
  tests/sbom/application-cdx-1.7-anonymized.json
```
