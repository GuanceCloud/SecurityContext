#!/usr/bin/env bash
set -euo pipefail

release_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    cat <<'USAGE'
Usage: bin/run-demo.sh [boot2|boot3] [JVM arguments...]

boot2 is the default (Java 8/11/17/21); boot3 requires Java 17/21.
JAVA_BIN             Java executable, default: java
DEMO_PORT            Local HTTP port, default: 18080
SECURITY_OUTPUT_DIR  Output directory; default: a new output/demo-TIMESTAMP-PID

Both security and SBOM are enabled. Telemetry is written locally by default.
Additional JVM arguments can override defaults or supply real code identity.
The demo binds to 127.0.0.1; use Ctrl-C for a graceful stop.
USAGE
    exit 0
fi

fixture=boot2
if [[ "${1:-}" == boot2 || "${1:-}" == boot3 ]]; then
    fixture="$1"
    shift
elif [[ $# -gt 0 && "$1" != -* ]]; then
    printf 'Unknown fixture: %s (expected boot2 or boot3)\n' "$1" >&2
    exit 2
fi

java_bin="${JAVA_BIN:-java}"
demo_port="${DEMO_PORT:-18080}"
if [[ ! "$demo_port" =~ ^[0-9]{1,5}$ ]] || (( 10#$demo_port < 1 || 10#$demo_port > 65535 )); then
    printf 'DEMO_PORT must be an integer from 1 to 65535\n' >&2
    exit 2
fi
demo_port="$((10#$demo_port))"
if ! command -v "$java_bin" >/dev/null 2>&1; then
    printf 'Java executable not found: %s. Set JAVA_BIN or use the documented Docker example.\n' "$java_bin" >&2
    exit 2
fi

agent="$release_root/lib/opentelemetry-javaagent-2.31.1.jar"
extension="$release_root/lib/securitycontext.jar"
application="$release_root/examples/apps/security-validation-$fixture.jar"
for artifact in "$agent" "$extension" "$application"; do
    if [[ ! -f "$artifact" ]]; then
        printf 'Missing distribution artifact: %s\n' "$artifact" >&2
        exit 2
    fi
done

output_dir="${SECURITY_OUTPUT_DIR:-$release_root/output/demo-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
printf 'SecurityContext output: %s\nDemo URL: http://127.0.0.1:%s\n' "$output_dir" "$demo_port" >&2

exec "$java_bin" \
    "-javaagent:$agent" \
    "-Dotel.javaagent.extensions=$extension" \
    "-Dotel.service.name=security-demo-$fixture" \
    -Dotel.traces.exporter=none \
    -Dotel.metrics.exporter=none \
    -Dotel.logs.exporter=none \
    -Dsecurity.enabled=true \
    -Dsecurity.sbom.enabled=true \
    "-Dsecurity.application.id=security-demo-$fixture" \
    "-Dsecurity.output=$output_dir" \
    "-Dsecurity.evidence.file=$output_dir/evidence.jsonl" \
    -Dserver.address=127.0.0.1 \
    "-Dserver.port=$demo_port" \
    "$@" \
    -jar "$application"
