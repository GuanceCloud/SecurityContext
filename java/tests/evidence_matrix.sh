#!/usr/bin/env bash
set -euo pipefail

# Exercise one endpoint at a time and assert the evidence emitted for that
# request. This avoids a total-count check hiding a missing source adapter.
base_url="${1:-http://127.0.0.1:18080}"
base_url="${base_url%/}"
evidence_file="${2:-${EVIDENCE_FILE:-}}"
if [ -z "$evidence_file" ] || [ ! -f "$evidence_file" ]; then
    printf 'evidence file is required and must exist: %s\n' "$evidence_file" >&2
    exit 2
fi
findings_file="$(dirname "$evidence_file")/findings.json"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

evidence_records() {
    python3 - "$evidence_file" <<'PY'
import json, sys
count = 0
try:
    stream = open(sys.argv[1], encoding='utf-8')
except OSError:
    print(0)
    raise SystemExit(0)
with stream:
    for line in stream:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get('event_name') == 'security.dataflow.observed':
            count += 1
print(count)
PY
}

finding_occurrences() {
    python3 - "$findings_file" "$1" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1], encoding='utf-8'))
except (OSError, json.JSONDecodeError):
    print(0)
    raise SystemExit(0)
rule = sys.argv[2]
print(sum(int(item.get('occurrences', 0)) for item in value.get('findings', []) if item.get('rule') == rule))
PY
}

wait_for_evidence_records() {
    local before="$1"
    local after
    for _ in $(seq 1 50); do
        after="$(evidence_records)"
        if [ "$after" -gt "$before" ]; then
            printf '%s\n' "$after"
            return 0
        fi
        sleep 0.1
    done
    printf '%s\n' "$after"
}

wait_for_finding_progress() {
    local rule="$1"
    local before="$2"
    local after
    for _ in $(seq 1 50); do
        after="$(finding_occurrences "$rule")"
        if [ "$after" -gt "$before" ]; then
            printf '%s\n' "$after"
            return 0
        fi
        sleep 0.1
    done
    printf 'finding occurrence did not increase for %s (before=%s)\n' "$rule" "$before" >&2
    return 1
}

assert_route() {
    local label="$1"
    local rule="$2"
    local source="$3"
    local sink="$4"
    shift 4
    local before after before_occurrences after_occurrences
    before_occurrences="$(finding_occurrences "$rule")"
    before="$(evidence_records)"
    sleep "${EVIDENCE_SAMPLE_WAIT:-1.1}"
    "$@" >/dev/null
    after_occurrences="$(wait_for_finding_progress "$rule" "$before_occurrences")"
    after="$(wait_for_evidence_records "$before")"
    python3 "$script_dir/assert_route_evidence.py" "$evidence_file" "$before" "$after" \
        --rule "$rule" --source "$source" --sink "$sink"
    printf 'finding occurrences: %s -> %s\n' "$before_occurrences" "$after_occurrences"
    printf 'evidence route passed: %s\n' "$label"
}

assert_forbidden() {
    local label="$1"
    local forbidden="$2"
    shift 2
    local before after before_occurrences after_occurrences
    before_occurrences="$(finding_occurrences "$forbidden")"
    before="$(evidence_records)"
    "$@" >/dev/null
    sleep 0.25
    after_occurrences="$(finding_occurrences "$forbidden")"
    [ "$after_occurrences" -eq "$before_occurrences" ] || {
        printf 'forbidden finding occurrences changed for %s: %s -> %s\n' "$label" "$before_occurrences" "$after_occurrences" >&2
        return 1
    }
    after="$(evidence_records)"
    python3 "$script_dir/assert_route_evidence.py" "$evidence_file" "$before" "$after" \
        --forbid-rule "$forbidden"
    printf 'finding occurrences unchanged: %s\n' "$before_occurrences"
    printf 'evidence boundary passed: %s\n' "$label"
}

curl_args=(curl --silent --show-error --fail --retry 3 --retry-delay 1)

assert_route dynamic-sql sql_injection http.request.parameter 'Statement\.executeQuery' \
    "${curl_args[@]}" --get --data-urlencode 'value=evidence-dynamic-sql' "$base_url/api/sql"
assert_forbidden parameterized-sql sql_injection \
    "${curl_args[@]}" --get --data-urlencode 'value=evidence-parameterized' "$base_url/api/sql/parameterized"
# Some JDBC proxies expose PreparedStatement execution through the generic
# Statement interface; the propagation still records prepareStatement.
assert_route prepared-template sql_injection http.request.parameter 'executeQuery' \
    "${curl_args[@]}" --get --data-urlencode 'value=evidence-prepared-template' "$base_url/api/sql/prepared-template"

assert_route json-map-body sql_injection http.request.body 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: application/json' \
    -d '{"value":"evidence-json-map"}' "$base_url/api/json/sql"
assert_route raw-reader-body sql_injection http.request.body 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: text/plain' \
    --data 'evidence-raw-reader' "$base_url/api/raw/reader/sql"
assert_route raw-jackson-body sql_injection http.request.body 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: application/json' \
    -d '{"value":"evidence-raw-jackson"}' "$base_url/api/raw/jackson/sql"
assert_route json-pojo-body sql_injection http.request.body 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: application/json' \
    -d '{"value":"evidence-json-pojo"}' "$base_url/api/pojo/sql"
assert_route json-list-body sql_injection http.request.body 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: application/json' \
    -d '["evidence-json-list"]' "$base_url/api/list/sql"
assert_route text-body sql_injection http.request.body 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: text/plain' \
    --data 'evidence-text-body' "$base_url/api/text/sql"
assert_route header-source sql_injection http.request.header 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'X-Security-Value: evidence-header' "$base_url/api/header/sql"
assert_route request-param-form sql_injection http.request.parameter 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'value=evidence-form' "$base_url/api/form/sql"
assert_route model-attribute-form sql_injection http.request.parameter 'Statement\.executeQuery' \
    "${curl_args[@]}" -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'value=evidence-model' "$base_url/api/model/sql"

assert_route shell-command command_injection http.request.parameter 'Runtime\.exec' \
    "${curl_args[@]}" --get --data-urlencode 'value=printf evidence-shell' "$base_url/api/command"
assert_route shell-command-lc command_injection http.request.parameter 'Runtime\.exec' \
    "${curl_args[@]}" --get --data-urlencode 'value=printf evidence-shell-lc' "$base_url/api/command/lc"
assert_forbidden ordinary-command-argument command_injection \
    "${curl_args[@]}" --get --data-urlencode 'value=evidence-argument' "$base_url/api/command/safe"
assert_route URL-address ssrf http.request.parameter 'HttpURLConnection' \
    "${curl_args[@]}" --get --data-urlencode 'host=127.0.0.1:8080' "$base_url/api/fetch/address"
assert_forbidden URL-response-to-constant-SQL sql_injection \
    "${curl_args[@]}" --get --data-urlencode 'url=http://127.0.0.1:8080/health' \
    "$base_url/api/fetch/response-sql"
for mode in raw uri interface; do
    assert_route "RestTemplate-$mode" ssrf http.request.parameter 'RestTemplate\.execute' \
        "${curl_args[@]}" --get --data-urlencode "mode=$mode" \
        --data-urlencode 'value=http://127.0.0.1:8080/health' "$base_url/api/fetch/rest-template"
done
assert_route RestTemplate-query http_request_input http.request.parameter 'RestTemplate\.execute' \
    "${curl_args[@]}" --get --data-urlencode 'mode=query' \
    --data-urlencode 'value=evidence-rest-query' "$base_url/api/fetch/rest-template"
assert_forbidden RestTemplate-body-only ssrf \
    "${curl_args[@]}" --get --data-urlencode 'mode=body' \
    --data-urlencode 'value=evidence-rest-body' "$base_url/api/fetch/rest-template"
assert_forbidden RestTemplate-response-to-constant-SQL sql_injection \
    "${curl_args[@]}" --get --data-urlencode 'url=http://127.0.0.1:8080/health' \
    "$base_url/api/fetch/rest-template-response-sql"
# A tainted query is observed at the request sink but does not make the
# destination address attacker controlled, so it must not be classified as
# SSRF.
assert_route URL-query http_request_input http.request.parameter 'HttpURLConnection' \
    "${curl_args[@]}" --get --data-urlencode 'query=evidence-query' "$base_url/api/fetch/query"
assert_forbidden URL-construction-only ssrf \
    "${curl_args[@]}" --get --data-urlencode 'url=http://security.example/health' "$base_url/api/fetch/construct"
assert_route normalized-path path_traversal http.request.parameter 'FileInputStream' \
    "${curl_args[@]}" --get \
    --data-urlencode 'path=/tmp/security-validation/../security-validation/input.txt' \
    "$base_url/api/file/normalize"
assert_route servlet-async-sql sql_injection http.request.parameter 'Statement\.executeQuery' \
    "${curl_args[@]}" --get --data-urlencode 'value=evidence-servlet-async' "$base_url/api/async/servlet"

if [ "${SMOKE_MODERN_CLIENTS:-0}" = 1 ]; then
    assert_route jdk-http-client ssrf http.request.parameter 'HttpClient' \
        "${curl_args[@]}" --get --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url/api/fetch/jdk"
fi

printf '%s\n' 'per-route evidence validation passed'
