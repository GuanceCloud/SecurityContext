#!/usr/bin/env bash
set -euo pipefail

# Validate that dataflow and SBOM switches remain independent in a real agent
# injection. Each leg gets a fresh output directory so absence is observable.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
validation_dir="${VALIDATION_DIR:-$repo_root/build/validation/switches-$(date +%Y%m%d-%H%M%S)}"
docker_context="${DOCKER_CONTEXT:-orbstack}"
image="${JAVA_IMAGE:-eclipse-temurin:17-jre}"
agent="${OTEL_AGENT_JAR:-$repo_root/build/deps/opentelemetry-javaagent-2.31.1.jar}"
extension="${EXTENSION_JAR:-$repo_root/security-otel-extension/build/libs/securitycontext.jar}"
jar="${APP_JAR:-$repo_root/samples/boot2/build/libs/security-validation-boot2.jar}"
mkdir -p "$validation_dir"

run_leg() {
    local name="$1" security="$2" sbom="$3" port="$4"
    local sql_rule="${5:-true}" expect_evidence="${6:-true}"
    local output="$validation_dir/$name"
    local container="security-switch-$name-$$"
    mkdir -p "$output"
    docker --context "$docker_context" run --rm --detach --name "$container" \
        --platform linux/arm64 --publish "$port:8080" \
        --volume "$jar:/opt/app/application.jar:ro" \
        --volume "$agent:/opt/otel/opentelemetry-javaagent.jar:ro" \
        --volume "$extension:/opt/otel/securitycontext.jar:ro" \
        --volume "$output:/opt/security-output" "$image" \
        java -javaagent:/opt/otel/opentelemetry-javaagent.jar \
        -Dotel.javaagent.extensions=/opt/otel/securitycontext.jar \
        -Dotel.service.name="$name" -Dotel.traces.exporter=none \
        -Dotel.metrics.exporter=none -Dotel.logs.exporter=none \
        -Dsecurity.enabled="$security" -Dsecurity.sbom.enabled="$sbom" \
        -Dsecurity.rules.sql_injection.enabled="$sql_rule" \
        -Dsecurity.evidence.file=/opt/security-output/evidence.jsonl \
        -Dsecurity.sbom.output=/opt/security-output/application.cdx.json \
        -jar /opt/app/application.jar > "$output/container-id"
    for attempt in $(seq 1 90); do
        if curl --silent --show-error --fail "http://127.0.0.1:$port/health" >/dev/null 2>&1; then break; fi
        if [ "$attempt" -eq 90 ]; then
            docker --context "$docker_context" logs "$container" > "$output/application.log" 2>&1 || true
            docker --context "$docker_context" stop "$container" >/dev/null || true
            return 1
        fi
        sleep 1
    done
    sql_ready=0
    for attempt in $(seq 1 20); do
        if curl --silent --show-error --fail --get --data-urlencode 'value=switch-marker' \
            "http://127.0.0.1:$port/api/sql" > "$output/sql-response.json"; then
            sql_ready=1
            break
        fi
        sleep 0.25
    done
    if [ "$sql_ready" -ne 1 ]; then
        docker --context "$docker_context" logs "$container" > "$output/application.log" 2>&1 || true
        docker --context "$docker_context" stop "$container" >/dev/null || true
        printf '%s\n' "SQL fixture did not become ready: $name" >&2
        return 1
    fi
    sleep 0.5
    docker --context "$docker_context" logs "$container" > "$output/application.log" 2>&1
    docker --context "$docker_context" stop "$container" >/dev/null

    if [ "$expect_evidence" = true ]; then
        [ -s "$output/evidence.jsonl" ] || { printf '%s\n' "security evidence missing: $name" >&2; return 1; }
    else
        if [ -s "$output/evidence.jsonl" ]; then
            printf '%s\n' "security evidence unexpectedly present: $name" >&2
            return 1
        fi
    fi
    if [ "$sbom" = true ]; then
        [ -s "$output/application.cdx.json" ] || { printf '%s\n' "SBOM missing: $name" >&2; return 1; }
        python3 "$repo_root/tests/cyclonedx_schema_check.py" "$output/application.cdx.json" \
            | tee "$output/sbom-check.log"
    else
        [ ! -e "$output/application.cdx.json" ] || { printf '%s\n' "SBOM unexpectedly present: $name" >&2; return 1; }
    fi
    printf 'switch validation passed: %s\n' "$name"
}

run_leg security-on-sbom-off true false 18096
run_leg security-off-sbom-on false true 18097 true false
run_leg sql-rule-off true true 18104 false false
run_leg both-off false false 18108 true false
printf 'switch validation artifacts: %s\n' "$validation_dir"
