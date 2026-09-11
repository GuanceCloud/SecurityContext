#!/usr/bin/env bash
set -euo pipefail

# Run a real OTel Java agent + extension against both Spring Boot fixtures.
# All logs, endpoint output and generated SBOM files remain under
# build/validation/<matrix-leg> for later review.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
validation_dir="${VALIDATION_DIR:-$repo_root/build/validation}"
docker_context="${DOCKER_CONTEXT:-orbstack}"
otel_version="${OTEL_JAVAAGENT_VERSION:-2.31.1}"
bundled_otel_agent="$repo_root/build/deps/opentelemetry-javaagent-$otel_version.jar"
otel_agent="${OTEL_AGENT_JAR:-$bundled_otel_agent}"
extension_jar="${EXTENSION_JAR:-$repo_root/security-otel-extension/build/libs/securitycontext.jar}"
compose_file="$repo_root/deploy/docker-compose.collector.yml"
findings_sample_seconds="${SECURITY_FINDINGS_SAMPLE_SECONDS:-300}"

mkdir -p "$validation_dir"

if [ ! -x "$repo_root/gradlew" ]; then
    printf '%s\n' 'Gradle wrapper is missing or not executable.' >&2
    exit 2
fi

if [ ! -f "$extension_jar" ]; then
    printf 'extension jar is missing: %s\n' "$extension_jar" >&2
    printf '%s\n' 'Build it first with scripts/orbstack_build.sh assemble.' >&2
    exit 2
fi

if [ ! -f "$otel_agent" ]; then
    mkdir -p "$(dirname "$otel_agent")"
    url="https://repo1.maven.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/$otel_version/opentelemetry-javaagent-$otel_version.jar"
    printf 'downloading OTel Java agent %s\n' "$otel_version"
    curl --fail --location --retry 3 --retry-delay 1 --output "$otel_agent.tmp" "$url"
    mv "$otel_agent.tmp" "$otel_agent"
fi

if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$otel_agent" | tee "$validation_dir/opentelemetry-javaagent.sha256"
    shasum -a 256 "$extension_jar" | tee "$validation_dir/securitycontext.sha256"
fi

run_leg() {
    local name="$1"
    local image="$2"
    local jar="$3"
    local port="$4"
    local modern_clients="${5:-0}"
    local leg_dir="$validation_dir/$name"
    local container="security-validation-$name-$$"
    local cleaned=0
    mkdir -p "$leg_dir"

    local -a telemetry_opts=(
        -Dotel.traces.exporter=none
        -Dotel.metrics.exporter=none
        -Dotel.logs.exporter=none
    )
    if [ "${START_COLLECTOR:-0}" = 1 ]; then
        telemetry_opts=(
            -Dotel.traces.exporter=otlp
            -Dotel.traces.sampler=always_off
            -Dotel.metrics.exporter=none
            -Dotel.logs.exporter=otlp
        -Dotel.exporter.otlp.endpoint=http://host.docker.internal:4318
            -Dotel.exporter.otlp.protocol=http/protobuf
        )
    fi

    : > "$leg_dir/application.log"
    : > "$leg_dir/requests.log"
    : > "$leg_dir/docker.inspect"

    printf 'starting %s with %s\n' "$name" "$image"
    docker --context "$docker_context" run --detach \
        --name "$container" \
        --platform linux/arm64 \
        --publish "$port:8080" \
        --volume "$jar:/opt/app/application.jar:ro" \
        --volume "$otel_agent:/opt/otel/opentelemetry-javaagent.jar:ro" \
        --volume "$extension_jar:/opt/otel/securitycontext.jar:ro" \
        --volume "$leg_dir:/opt/security-output" \
        "$image" \
        java \
        -javaagent:/opt/otel/opentelemetry-javaagent.jar \
        -Dotel.javaagent.extensions=/opt/otel/securitycontext.jar \
        -Dotel.service.name="$name" \
        "${telemetry_opts[@]}" \
        -Dsecurity.output=/opt/security-output \
        -Dsecurity.findings.sample.seconds="$findings_sample_seconds" \
        -Dsecurity.evidence.file=/opt/security-output/evidence.jsonl \
        -Dsecurity.sbom.output=/opt/security-output/application.cdx.json \
        -Dsecurity.sbom.enabled=true \
        -jar /opt/app/application.jar \
        > "$leg_dir/container-id"

    local container_id
    container_id="$(sed -n '1p' "$leg_dir/container-id")"
    printf '%s\n' "$container_id" > "$leg_dir/container-id"

    cleanup_leg() {
        local result="$1"
        if [ "$cleaned" -eq 0 ]; then
            cleaned=1
            if docker --context "$docker_context" inspect "$container" >/dev/null 2>&1; then
                if [ "$result" -eq 0 ]; then
                    docker --context "$docker_context" stop --time 10 "$container" >/dev/null 2>&1 || true
                else
                    docker --context "$docker_context" rm --force "$container" >/dev/null 2>&1 || true
                fi
                docker --context "$docker_context" logs "$container" > "$leg_dir/application.log" 2>&1 || true
                docker --context "$docker_context" inspect "$container" > "$leg_dir/docker.inspect" 2>/dev/null || true
                docker --context "$docker_context" rm "$container" >/dev/null 2>&1 || true
            fi
        fi
        return "$result"
    }
    trap 'cleanup_leg "$?"' RETURN

    wait_for_final_snapshot() {
        for _ in $(seq 1 40); do
            if [ -s "$leg_dir/health.json" ] && python3 - "$leg_dir/health.json" <<'PY'
import json, sys
try:
    health = json.load(open(sys.argv[1], encoding='utf-8'))
    counts = health.get('counts', {})
    ok = (health.get('active_requests', 0) == 0 and
          counts.get('requests_started', 0) == counts.get('requests_completed', 0))
except (OSError, ValueError, TypeError):
    ok = False
raise SystemExit(0 if ok else 1)
PY
            then
                sleep 2
                if python3 - "$leg_dir/health.json" <<'PY'
import json, sys
health = json.load(open(sys.argv[1], encoding='utf-8'))
counts = health.get('counts', {})
raise SystemExit(0 if health.get('active_requests', 0) == 0 and
                 counts.get('requests_started', 0) == counts.get('requests_completed', 0) else 1)
PY
                then
                    return 0
                fi
            fi
            sleep 0.25
        done
        printf 'final snapshot did not settle for %s\n' "$name" >&2
        return 1
    }

    for attempt in $(seq 1 90); do
        if curl --silent --show-error --fail "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
            break
        fi
        if [ "$attempt" -eq 90 ]; then
            printf 'application did not become ready: %s\n' "$name" >&2
            docker --context "$docker_context" logs "$container" | tee "$leg_dir/application.log" >&2 || true
            return 1
        fi
        sleep 1
    done

    if [ "${ASSERT_ROUTE_EVIDENCE:-0}" = 1 ]; then
        # The route matrix needs a file target before its normalized-path case.
        curl --silent --show-error --fail --retry 3 --retry-delay 1 --get \
            --data-urlencode 'path=/tmp/security-validation/input.txt' \
            --data-urlencode 'value=security-evidence-setup' \
            "http://127.0.0.1:$port/api/file/write" >/dev/null
        if [ "$modern_clients" = 1 ]; then
            SMOKE_MODERN_CLIENTS=1 EVIDENCE_FILE="$leg_dir/evidence.jsonl" \
                "$repo_root/tests/evidence_matrix.sh" "http://127.0.0.1:$port" \
                "$leg_dir/evidence.jsonl" | tee "$leg_dir/evidence-routes.log"
        else
            EVIDENCE_FILE="$leg_dir/evidence.jsonl" "$repo_root/tests/evidence_matrix.sh" \
                "http://127.0.0.1:$port" "$leg_dir/evidence.jsonl" \
                | tee "$leg_dir/evidence-routes.log"
        fi
    fi
    if [ "$modern_clients" = 1 ]; then
        SMOKE_MODERN_CLIENTS=1 "$repo_root/tests/smoke.sh" "http://127.0.0.1:$port" \
            | tee "$leg_dir/requests.log"
    else
        "$repo_root/tests/smoke.sh" "http://127.0.0.1:$port" | tee "$leg_dir/requests.log"
    fi
    wait_for_final_snapshot

    if [ ! -s "$leg_dir/application.cdx.json" ]; then
        printf 'SBOM output is missing or empty for %s\n' "$name" >&2
        return 1
    fi
    python3 "$repo_root/tests/cyclonedx_schema_check.py" "$leg_dir/application.cdx.json" \
        | tee "$leg_dir/sbom-check.log"
    python3 "$repo_root/tests/assert_evidence_association.py" \
        "$leg_dir/evidence.jsonl" "$leg_dir/application.cdx.json" \
        | tee "$leg_dir/evidence-association.log"
    cleanup_leg 0
    trap - RETURN
    printf 'completed %s\n' "$name"
}

if [ "${START_COLLECTOR:-0}" = 1 ]; then
    docker --context "$docker_context" compose -f "$compose_file" up -d
fi

matrix_legs="${MATRIX_LEGS:-all}"
want_leg() {
    [ "$matrix_legs" = all ] || case ",$matrix_legs," in *,"$1",*) return 0 ;; *) return 1 ;; esac
}

if want_leg boot2-java8; then
    run_leg boot2-java8 eclipse-temurin:8-jre \
        "$repo_root/samples/boot2/build/libs/security-validation-boot2.jar" 18080
fi
if want_leg boot2-java11; then
    run_leg boot2-java11 eclipse-temurin:11-jre \
        "$repo_root/samples/boot2/build/libs/security-validation-boot2.jar" 18082
fi
if want_leg boot3-java17; then
    run_leg boot3-java17 eclipse-temurin:17-jre \
        "$repo_root/samples/boot3/build/libs/security-validation-boot3.jar" 18081 1
fi
if want_leg boot3-java21; then
    run_leg boot3-java21 eclipse-temurin:21-jre \
        "$repo_root/samples/boot3/build/libs/security-validation-boot3.jar" 18083 1
fi

printf 'injection validation artifacts: %s\n' "$validation_dir"
