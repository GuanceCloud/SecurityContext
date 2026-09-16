#!/usr/bin/env python3
"""Check that the final local ledger snapshot contains all emitted finding references."""

import json
import sys
from pathlib import Path


if len(sys.argv) != 2:
    raise SystemExit("usage: assert_ledger_flush.py LEG_OUTPUT_DIR")

directory = Path(sys.argv[1])
health = json.loads((directory / "health.json").read_text(encoding="utf-8"))
findings = json.loads((directory / "findings.json").read_text(encoding="utf-8"))

counts = health.get("counts", {})
if health.get("active_requests", 0) != 0:
    raise SystemExit("ledger still has active requests")
if counts.get("requests_started", 0) != counts.get("requests_completed", 0):
    raise SystemExit("health snapshot has incomplete request counters")

events = []
for line in (directory / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    record = json.loads(line)
    if record.get("event_name") == "security.dataflow.observed":
        events.append(record)

rows = {str(item.get("finding_id")): item for item in findings.get("findings", [])}
event_ids = {str(item.get("finding_id")) for item in events}
missing = sorted(event_ids - rows.keys())
if missing:
    raise SystemExit("final findings snapshot is missing dataflow finding IDs: " + ", ".join(missing))

occurrences = sum(int(item.get("occurrences", 0)) for item in rows.values())
if occurrences < len(events):
    raise SystemExit("finding occurrence total is lower than emitted dataflow records")

print("ledger flush consistency passed: requests=%d dataflow=%d finding_rows=%d occurrences=%d" %
      (counts.get("requests_completed", 0), len(events), len(rows), occurrences))
