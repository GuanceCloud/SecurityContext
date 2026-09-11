#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker_context="${DOCKER_CONTEXT:-orbstack}"
docker_cmd=(docker --context "$docker_context")
app_jar="${APP_JAR:-$repo_root/samples/boot2/build/libs/security-validation-boot2.jar}"
otel_agent="${OTEL_AGENT:-$repo_root/build/deps/opentelemetry-javaagent-2.31.1.jar}"
extension_jar="${EXTENSION_JAR:-$repo_root/security-otel-extension/build/libs/securitycontext.jar}"
cli="${SECURITYCTL:-$repo_root/scripts/securityctl.py}"
java_image="${JAVA_IMAGE:-eclipse-temurin:17-jre}"
port="${PORT:-18120}"
output="${VALIDATION_OUTPUT:-$repo_root/build/validation/product-e2e-$(date +%Y%m%d-%H%M%S)}"
base_url="http://127.0.0.1:$port"
container="security-product-e2e-$$"

for required in "$app_jar" "$otel_agent" "$extension_jar" "$cli"; do
    [ -f "$required" ] || { printf 'required artifact is missing: %s\n' "$required" >&2; exit 2; }
done
mkdir -p "$output"
for file in health.json findings.json runs.json control.json evidence.jsonl application.cdx.json no-traffic.json no-traffic-verify.json baseline.json candidate.json verification.json query-findings.json query-runs.json pause-status.json resume-status.json active-exception.json expired-exception.json; do
    rm -f "$output/$file"
done

cleanup() {
    set +e
    if "${docker_cmd[@]}" inspect "$container" >/dev/null 2>&1; then
        "${docker_cmd[@]}" logs "$container" >"$output/application.log" 2>&1
        "${docker_cmd[@]}" inspect "$container" >"$output/docker.inspect" 2>/dev/null
        "${docker_cmd[@]}" stop "$container" >/dev/null 2>&1
        "${docker_cmd[@]}" rm "$container" >/dev/null 2>&1
    fi
}
trap cleanup EXIT

shasum -a 256 "$app_jar" "$otel_agent" "$extension_jar" | tee "$output/artifacts.sha256"

"${docker_cmd[@]}" run --detach --name "$container" --platform linux/arm64 --publish "$port:8080" \
    --volume "$app_jar:/opt/app/application.jar:ro" \
    --volume "$otel_agent:/opt/otel/opentelemetry-javaagent.jar:ro" \
    --volume "$extension_jar:/opt/otel/securitycontext.jar:ro" \
    --volume "$output:/opt/security-output" "$java_image" java \
    -javaagent:/opt/otel/opentelemetry-javaagent.jar \
    -Dotel.javaagent.extensions=/opt/otel/securitycontext.jar \
    -Dotel.service.name=security-product-e2e \
    -Dotel.traces.exporter=none -Dotel.metrics.exporter=none -Dotel.logs.exporter=none \
    -Dsecurity.output=/opt/security-output \
    -Dsecurity.evidence.file=/opt/security-output/evidence.jsonl \
    -Dsecurity.sbom.output=/opt/security-output/application.cdx.json \
    -Dsecurity.code.repository=securitycontext-validation \
    -Dsecurity.code.commit="${SECURITY_CODE_COMMIT:-product-e2e}" \
    -Dsecurity.code.build-id="${SECURITY_CODE_BUILD_ID:-product-e2e-$(date +%Y%m%d%H%M%S)}" \
    -jar /opt/app/application.jar >"$output/container-id"

wait_file() {
    local file="$1"
    for _ in $(seq 1 90); do
        [ -s "$file" ] && return 0
        sleep 1
    done
    printf 'timed out waiting for %s\n' "$file" >&2
    return 1
}

wait_status() {
    local expected="$1" result=""
    for _ in $(seq 1 30); do
        result="$(python3 "$cli" --dir "$output" status 2>/dev/null || true)"
        printf '%s\n' "$result" >"$output/status-$expected.json"
        if printf '%s' "$result" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", ""))' 2>/dev/null | grep -Fxq "$expected"; then return 0; fi
        sleep 1
    done
    printf 'expected status %s, latest: %s\n' "$expected" "$result" >&2
    return 1
}

wait_status_any() {
    local result="" status expected
    for _ in $(seq 1 30); do
        result="$(python3 "$cli" --dir "$output" status 2>/dev/null || true)"
        printf '%s\n' "$result" >"$output/status-health-route.json"
        status="$(printf '%s' "$result" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", ""))' 2>/dev/null || true)"
        for expected in "$@"; do
            if [ "$status" = "$expected" ]; then return 0; fi
        done
        sleep 1
    done
    printf 'expected one of [%s], latest: %s\n' "$*" "$result" >&2
    return 1
}

assert_json() {
    python3 - "$1" <<'PY'
import json, sys
json.load(open(sys.argv[1], encoding='utf-8'))
PY
}

wait_file "$output/health.json"
wait_status no_traffic


python3 "$cli" --dir "$output" run-start --id no-traffic-run --case product-no-traffic \
    --rule sql_injection --suite product-e2e --fixture sql-risk --expected-requests 1 --ttl 300 >"$output/no-traffic-start.json"
python3 "$cli" --dir "$output" run-stop --output "$output/no-traffic.json" >"$output/no-traffic-stop.json"
set +e
python3 "$cli" --dir "$output" verify --baseline "$output/no-traffic.json" --candidate "$output/no-traffic.json" \
    --output "$output/no-traffic-verify.json" >"$output/no-traffic-verify.stdout"
verify_rc=$?
set -e
[ "$verify_rc" -eq 3 ] || { printf 'expected inconclusive exit 3, got %s\n' "$verify_rc" >&2; exit 1; }
python3 - "$output/no-traffic-verify.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1], encoding='utf-8'))['outcome'] == 'inconclusive'
PY

curl --silent --show-error --fail --retry 3 --retry-delay 1 "$base_url/health" >"$output/readiness.json"
# Spring/Tomcat may read ordinary request headers (for example Accept) while
# dispatching a no-sink endpoint. Accept both valid coverage states and retain
# the observed status; the core ledger test covers the zero-source state.
wait_status_any no_source_observed no_sink_observed
curl --silent --show-error --fail --retry 3 --retry-delay 1 -H 'Content-Type: application/json' \
    -d '{"value":"product-source-only"}' "$base_url/api/json" >"$output/source-only.json"
wait_status no_sink_observed
curl --silent --show-error --fail --retry 3 --retry-delay 1 "$base_url/api/sql/constant" >"$output/sink-only.json"
wait_status observed

case_id="product-sql-case"
common=(--case "$case_id" --rule sql_injection --suite product-e2e --fixture sql-risk --expected-requests 1 --ttl 300)
python3 "$cli" --dir "$output" run-start --id baseline-run "${common[@]}" >"$output/baseline-start.json"
curl --silent --show-error --fail --retry 3 --retry-delay 1 --get --data-urlencode 'value=product-risk-marker' \
    "$base_url/api/sql" >"$output/baseline-response.json"
python3 "$cli" --dir "$output" run-stop --output "$output/baseline.json" >"$output/baseline-stop.json"
python3 "$cli" --dir "$output" run-start --id candidate-run "${common[@]}" >"$output/candidate-start.json"
curl --silent --show-error --fail --retry 3 --retry-delay 1 --get --data-urlencode 'value=product-risk-marker' \
    "$base_url/api/sql/parameterized" >"$output/candidate-response.json"
python3 "$cli" --dir "$output" run-stop --output "$output/candidate.json" >"$output/candidate-stop.json"

python3 "$cli" --dir "$output" verify --baseline "$output/baseline.json" --candidate "$output/candidate.json" \
    --output "$output/verification.json" >"$output/verification.stdout"
python3 - "$output/verification.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
assert value['outcome'] == 'not_observed', value
assert value['case_id'] == 'product-sql-case', value
PY
python3 "$cli" --dir "$output" query findings --rule sql_injection >"$output/query-findings.json"
python3 "$cli" --dir "$output" query runs --case "$case_id" >"$output/query-runs.json"

python3 - "$output/findings.json" "$output/runs.json" "$output/query-findings.json" "$output/query-runs.json" <<'PY'
import json, sys
findings = json.load(open(sys.argv[1], encoding='utf-8'))
runs = json.load(open(sys.argv[2], encoding='utf-8'))
assert json.load(open(sys.argv[3], encoding='utf-8'))['total'] >= 1
assert json.load(open(sys.argv[4], encoding='utf-8'))['total'] == 2
items = findings['findings']
assert items
assert len({item['finding_id'] for item in items}) == 1
finding = items[0]
assert finding['assessment'] in ('observation', 'candidate_risk')
assert finding['validation'] == 'unvalidated'
assert finding['assessment'] != 'confirmed'
assert finding['occurrences'] >= 1
for run_id in ('baseline-run', 'candidate-run'):
    run = next(item for item in runs['runs'] if item['run_id'] == run_id)
    assert run['status'] == 'closed', run
    assert run['case_id'] == 'product-sql-case', run
    assert run['conditions']['suite'] == 'product-e2e', run
    assert run['conditions']['fixture'] == 'sql-risk', run
    assert run['identity']['code']['repository'], run
    assert run['identity']['code']['commit'], run
    assert run['identity']['code']['build_id'], run
    assert run['requests'] == 1, run
    assert run['source_requests'] == 1, run
    assert run['sink_requests'] == 1, run
    assert run['error_requests'] == 0, run
    assert run['incomplete_requests'] == 0, run
baseline = next(item for item in runs['runs'] if item['run_id'] == 'baseline-run')
candidate = next(item for item in runs['runs'] if item['run_id'] == 'candidate-run')
assert baseline['observations'] > 0, baseline
assert candidate['observations'] == 0, candidate
PY

boundary_case_id="product-sql-source-boundary"
boundary_common=(--case "$boundary_case_id" --rule sql_injection --suite product-e2e --fixture sql-risk --expected-requests 1 --ttl 300)
python3 "$cli" --dir "$output" run-start --id boundary-baseline-run "${boundary_common[@]}" >"$output/boundary-baseline-start.json"
curl --silent --show-error --fail --retry 3 --retry-delay 1 --get --data-urlencode 'value=product-boundary-marker' \
    "$base_url/api/sql" >"$output/boundary-baseline-response.json"
python3 "$cli" --dir "$output" run-stop --output "$output/boundary-baseline.json" >"$output/boundary-baseline-stop.json"
python3 "$cli" --dir "$output" run-start --id boundary-candidate-run "${boundary_common[@]}" >"$output/boundary-candidate-start.json"
curl --silent --show-error --fail --retry 3 --retry-delay 1 "$base_url/api/sql/constant" >"$output/boundary-candidate-response.json"
python3 "$cli" --dir "$output" run-stop --output "$output/boundary-candidate.json" >"$output/boundary-candidate-stop.json"
set +e
python3 "$cli" --dir "$output" verify --baseline "$output/boundary-baseline.json" --candidate "$output/boundary-candidate.json" \
    --output "$output/boundary-verification.json" >"$output/boundary-verification.stdout"
boundary_verify_rc=$?
set -e
[ "$boundary_verify_rc" -eq 3 ] || { printf 'expected boundary verify inconclusive exit 3, got %s\n' "$boundary_verify_rc" >&2; exit 1; }
python3 - "$output/boundary-verification.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
assert value['outcome'] == 'inconclusive', value
assert any(reason.startswith('candidate_missing_baseline_source:') for reason in value['reasons']), value
PY

positive_case_id="product-sql-observed"
positive_common=(--case "$positive_case_id" --rule sql_injection --suite product-e2e --fixture sql-risk --expected-requests 1 --ttl 300)
python3 "$cli" --dir "$output" run-start --id positive-baseline-run "${positive_common[@]}" >"$output/positive-baseline-start.json"
curl --silent --show-error --fail --retry 3 --retry-delay 1 --get --data-urlencode 'value=product-positive-baseline' \
    "$base_url/api/sql" >"$output/positive-baseline-response.json"
python3 "$cli" --dir "$output" run-stop --output "$output/positive-baseline.json" >"$output/positive-baseline-stop.json"
python3 "$cli" --dir "$output" run-start --id positive-candidate-run "${positive_common[@]}" >"$output/positive-candidate-start.json"
curl --silent --show-error --fail --retry 3 --retry-delay 1 --get --data-urlencode 'value=product-positive-candidate' \
    "$base_url/api/sql" >"$output/positive-candidate-response.json"
python3 "$cli" --dir "$output" run-stop --output "$output/positive-candidate.json" >"$output/positive-candidate-stop.json"
python3 "$cli" --dir "$output" verify --baseline "$output/positive-baseline.json" --candidate "$output/positive-candidate.json" \
    --output "$output/positive-verification.json" >"$output/positive-verification.stdout"
python3 - "$output/positive-verification.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
assert value['outcome'] == 'observed', value
PY

python3 "$cli" --dir "$output" pause >"$output/pause-status.json"
wait_status paused
before_occurrences="$(python3 - "$output/findings.json" <<'PY'
import json, sys
print(sum(item.get('occurrences', 0) for item in json.load(open(sys.argv[1], encoding='utf-8'))['findings']))
PY
)"
curl --silent --show-error --fail --retry 3 --retry-delay 1 --get --data-urlencode 'value=product-paused-marker' \
    "$base_url/api/sql" >"$output/paused-response.json"
sleep 2
after_occurrences="$(python3 - "$output/findings.json" <<'PY'
import json, sys
print(sum(item.get('occurrences', 0) for item in json.load(open(sys.argv[1], encoding='utf-8'))['findings']))
PY
)"
[ "$after_occurrences" -eq "$before_occurrences" ] || { printf 'paused request changed finding occurrences\n' >&2; exit 1; }
python3 "$cli" --dir "$output" resume >"$output/resume-status.json"
wait_status observed
curl --silent --show-error --fail --retry 3 --retry-delay 1 --get --data-urlencode 'value=product-resumed-marker' \
    "$base_url/api/sql" >"$output/resumed-response.json"

finding_id="$(python3 - "$output/findings.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding='utf-8'))['findings'][0]['finding_id'])
PY
)"
python3 "$cli" --dir "$output" exception-add --finding "$finding_id" --decision accepted_risk \
    --reason 'product validation scoped review' --ttl 2 >"$output/active-exception.json"
python3 - "$output/control.json" "$output/findings.json" <<'PY'
import json, sys
control = json.load(open(sys.argv[1], encoding='utf-8'))
entry = control['exceptions'][0]
assert entry['scope']['application_id']
assert entry['scope']['finding_id']
assert entry['reason']
assert entry['expires_at']
finding = next(item for item in json.load(open(sys.argv[2], encoding='utf-8'))['findings']
               if item['finding_id'] == entry['scope']['finding_id'])
assert finding['triage']['decision'] == 'accepted_risk', finding
assert finding['triage']['reason'] == 'product validation scoped review', finding
PY
sleep 3
python3 "$cli" --dir "$output" query findings --finding "$finding_id" >"$output/expired-exception.json"
python3 - "$output/expired-exception.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
assert value['total'] == 1, value
assert value['items'][0]['triage']['decision'] == 'unreviewed', value
PY

for file in health.json findings.json runs.json control.json application.cdx.json; do
    [ -s "$output/$file" ] || { printf 'missing product output: %s\n' "$output/$file" >&2; exit 1; }
    assert_json "$output/$file"
done
printf 'product validation passed: %s\n' "$output"
