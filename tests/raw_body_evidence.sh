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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lines() { wc -l < "$evidence_file" | tr -d ' '; }

check_route() {
    local label="$1"
    shift
    local before after
    before="$(lines)"
    curl --silent --show-error --fail --retry 3 --retry-delay 1 "$@" >/dev/null
    for _ in $(seq 1 50); do
        after="$(lines)"
        [ "$after" -gt "$before" ] && break
        sleep 0.1
    done
    python3 "$script_dir/assert_route_evidence.py" "$evidence_file" "$before" "$after" \
        --rule sql_injection --source http.request.body --sink 'Statement\.executeQuery'
    printf 'raw body route passed: %s\n' "$label"
}

check_route reader -H 'Content-Type: text/plain' --data 'raw-reader-check' \
    "$base_url/api/raw/reader/sql"
check_route jackson -H 'Content-Type: application/json' \
    -d '{"value":"raw-jackson-check"}' "$base_url/api/raw/jackson/sql"

check_response_control() {
    local label="$1"
    local endpoint="$2"
    local control_before control_after
    control_before="$(lines)"
    curl --silent --show-error --fail --retry 3 --retry-delay 1 --get \
        --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url$endpoint" >/dev/null
    sleep 0.25
    control_after="$(lines)"
    python3 "$script_dir/assert_route_evidence.py" "$evidence_file" "$control_before" "$control_after" \
        --forbid-rule sql_injection
    python3 - "$evidence_file" "$control_before" "$control_after" "$label" <<'PY'
import json
import sys

path, start, end = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
records = [json.loads(line) for line in open(path, encoding="utf-8").readlines()[start:end] if line.strip()]
if any(source.get("type") == "http.request.body"
       for record in records for source in record.get("sources", [])):
    raise SystemExit("remote response was incorrectly registered as HTTP request body")
print("remote response %s control passed: %d records" % (sys.argv[4], len(records)))
PY
    printf 'remote response control passed: %s\n' "$label"
}

check_response_control URLConnection /api/fetch/response-sql
check_response_control RestTemplate /api/fetch/rest-template-response-sql
printf '%s\n' 'raw servlet body evidence validation passed'
