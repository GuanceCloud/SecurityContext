#!/usr/bin/env python3
"""Verify SecurityEvidence component links resolve into the emitted SBOM."""

import json
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: assert_evidence_association.py EVIDENCE.jsonl SBOM.json")

evidence_path, sbom_path = sys.argv[1:]
with open(sbom_path, "r", encoding="utf-8") as stream:
    sbom = json.load(stream)
serial = sbom.get("serialNumber")
refs = {str(component.get("bom-ref")) for component in sbom.get("components", [])}
if not serial or not refs:
    raise SystemExit("SBOM has no serialNumber or components")

records = 0
unresolved = 0
for line in open(evidence_path, "r", encoding="utf-8"):
    if not line.strip():
        continue
    record = json.loads(line)
    if record.get("event_name") != "security.dataflow.observed":
        continue
    component = record.get("component") or {}
    if component.get("sbom_id") != serial:
        raise SystemExit("evidence sbom_id does not match SBOM serialNumber")
    if not isinstance(component.get("revision"), int) or component["revision"] < 1:
        raise SystemExit("evidence component revision is invalid")
    records += 1
    if component.get("status") == "resolved":
        if component.get("bom-ref") not in refs:
            raise SystemExit("resolved evidence bom-ref is absent from SBOM")
    else:
        unresolved += 1

if records == 0:
    raise SystemExit("evidence file has no records")
print("evidence/SBOM association passed: %d records, %d unresolved" % (records, unresolved))
