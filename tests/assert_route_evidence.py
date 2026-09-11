#!/usr/bin/env python3
"""Check only the evidence records emitted by one request interval."""

import argparse
import json
import re
import sys


parser = argparse.ArgumentParser()
parser.add_argument("path")
parser.add_argument("start", type=int)
parser.add_argument("end", type=int)
parser.add_argument("--rule")
parser.add_argument("--source")
parser.add_argument("--sink")
parser.add_argument("--forbid-rule", action="append", default=[])
args = parser.parse_args()

with open(args.path, "r", encoding="utf-8") as stream:
    records = []
    for line in stream:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event_name") == "security.dataflow.observed":
            records.append(record)
records = records[args.start : args.end]

forbidden = {rule for rule in args.forbid_rule}
for record in records:
    if record.get("rule") in forbidden:
        raise SystemExit(
            "forbidden rule %s appeared in request interval" % record.get("rule")
        )

if args.rule is None:
    print("route evidence passed: %d records" % len(records))
    raise SystemExit(0)

matches = []
for record in records:
    if record.get("rule") != args.rule:
        continue
    if args.source and not any(
        args.source in str(source.get("type", ""))
        for source in record.get("sources", [])
    ):
        continue
    if args.sink and not re.search(args.sink, record.get("sink", {}).get("function", "")):
        continue
    matches.append(record)

if not matches:
    observed = [
        {
            "rule": record.get("rule"),
            "sources": [source.get("type") for source in record.get("sources", [])],
            "sink": record.get("sink", {}).get("function"),
        }
        for record in records
    ]
    raise SystemExit(
        "expected route evidence rule=%s source=%s sink=%s; observed=%s"
        % (args.rule, args.source, args.sink, observed)
    )

print("route evidence passed: %s (%d matching records, %d total)" % (args.rule, len(matches), len(records)))
