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
    after="$before"
    for _ in $(seq 1 50); do
        after="$(lines)"
        [ "$after" -gt "$before" ] && break
        sleep 0.1
    done
    python3 "$script_dir/assert_route_evidence.py" "$evidence_file" "$before" "$after" \
        --rule sql_injection --source http.request.body --sink 'Statement\.executeQuery'
    printf 'body binding route passed: %s\n' "$label"
}

check_route map -H 'Content-Type: application/json' \
    -d '{"value":"body-map-check"}' "$base_url/api/json/sql"
check_route pojo -H 'Content-Type: application/json' \
    -d '{"value":"body-pojo-check"}' "$base_url/api/pojo/sql"
check_route list -H 'Content-Type: application/json' \
    -d '["body-list-check"]' "$base_url/api/list/sql"
check_route text -H 'Content-Type: text/plain' \
    --data 'body-text-check' "$base_url/api/text/sql"
printf '%s\n' 'Spring body binding evidence validation passed'
