#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://127.0.0.1:18080}"
base_url="${base_url%/}"
evidence_file="${2:-${EVIDENCE_FILE:-}}"
if [ -z "$evidence_file" ]; then
    printf 'evidence file is required\n' >&2
    exit 2
fi
mkdir -p "$(dirname "$evidence_file")"
touch "$evidence_file"

lines() { wc -l < "$evidence_file" | tr -d ' '; }
curl_common=(curl --silent --show-error --fail --retry 3 --retry-delay 1)
before="$(lines)"

# Even trace IDs intentionally go through the polluted SQL sink. Odd trace IDs
# read the same value but use the parameterized control endpoint.
for i in $(seq 0 15); do
    trace_id="$(printf '%032x' $((i + 1)))"
    span_id="$(printf '%016x' $((i + 101)))"
    if [ $((i % 2)) -eq 0 ]; then
        "${curl_common[@]}" --get \
            -H "traceparent: 00-$trace_id-$span_id-01" \
            --data-urlencode 'value=concurrent-shared-marker' "$base_url/api/sql" >/dev/null &
    else
        "${curl_common[@]}" --get \
            -H "traceparent: 00-$trace_id-$span_id-01" \
            --data-urlencode 'value=concurrent-shared-marker' "$base_url/api/sql/parameterized" >/dev/null &
    fi
done
wait

after="$before"
for _ in $(seq 1 50); do
    after="$(lines)"
    [ "$after" -gt "$before" ] && break
    sleep 0.1
done

python3 - "$evidence_file" "$before" "$after" <<'PY'
import json
import sys

path, start, end = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
records = [json.loads(line) for line in open(path, encoding="utf-8").readlines()[start:end] if line.strip()]
dynamic = {"%032x" % (i + 1) for i in range(0, 16, 2)}
control = {"%032x" % (i + 1) for i in range(1, 16, 2)}
seen = {trace: 0 for trace in dynamic}
for record in records:
    trace = record.get("trace_id")
    if trace not in dynamic | control:
        raise SystemExit("unexpected trace in concurrent evidence: %s" % trace)
    if trace in control:
        raise SystemExit("control trace emitted evidence: %s" % trace)
    if record.get("rule") != "sql_injection":
        raise SystemExit("dynamic trace emitted unexpected rule: %s" % record.get("rule"))
    seen[trace] += 1
missing = [trace for trace, count in seen.items() if count == 0]
if missing:
    raise SystemExit("dynamic traces missing evidence: %s" % missing)
if len({record.get("evidence_id") for record in records}) != len(records):
    raise SystemExit("evidence IDs were reused across concurrent requests")
print("concurrent trace isolation passed: %d records, %d dynamic traces, %d controls" %
      (len(records), len(dynamic), len(control)))
PY

# Exercise request cleanup after an exception, then reuse the worker pool for
# a control request. Neither request has a polluted template sink.
cleanup_before="$(lines)"
for i in $(seq 0 3); do
    trace_id="$(printf '%032x' $((1001 + i)))"
    span_id="$(printf '%016x' $((2001 + i)))"
    status="$(curl --silent --show-error --retry 3 --retry-delay 1 \
        -o /dev/null -w '%{http_code}' \
        -H "traceparent: 00-$trace_id-$span_id-01" \
        --get --data-urlencode 'value=cleanup-exception' "$base_url/api/exception")"
    [ "$status" = 500 ] || { printf 'expected exception status 500, got %s\n' "$status" >&2; exit 1; }
done
status="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -o /dev/null -w '%{http_code}' \
    -H 'traceparent: 00-000000000000000000000000000003e9-00000000000007d1-01' \
    --get --data-urlencode 'value=cleanup-control' "$base_url/api/sql/parameterized")"
[ "$status" = 200 ] || { printf 'expected cleanup control status 200, got %s\n' "$status" >&2; exit 1; }
sleep 0.5
cleanup_after="$(lines)"
if [ "$cleanup_after" -ne "$cleanup_before" ]; then
    printf 'exception cleanup emitted %s evidence records\n' "$((cleanup_after - cleanup_before))" >&2
    exit 1
fi
printf '%s\n' 'exception cleanup and thread reuse passed'
